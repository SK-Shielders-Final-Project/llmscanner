"""
Vrompt — Probe 모듈

각 프로브는 BaseProbe를 상속하여 특정 취약점 카테고리의 프롬프트를 정의한다.
프롬프트 데이터는 data.json에서 로딩한다.
"""

import json
import os
from dataclasses import dataclass
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from dotenv import load_dotenv

# .env 로드
load_dotenv(override=True)

# dataset 경로
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# 리스트 타입 필드: 병합 시 concatenate
_LIST_FIELDS = {"prompts", "triggers", "encoding_payloads", "extra_prompts"}


def _load_json(filename):
    """단일 JSON 파일 로딩"""
    path = os.path.join(_DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _merge_data(base, other):
    """두 데이터셋을 병합 — 동일 카테고리의 리스트 필드는 concatenate"""
    merged = {}
    all_keys = set(base.keys()) | set(other.keys())
    for key in all_keys:
        if key in base and key in other:
            merged_cat = dict(base[key])
            for field in _LIST_FIELDS:
                if field in other[key]:
                    merged_cat[field] = merged_cat.get(field, []) + other[key][field]
            merged[key] = merged_cat
        elif key in base:
            merged[key] = base[key]
        else:
            merged[key] = other[key]
    return merged


def _load_data():
    """PLATFORM / NORMAL 환경변수에 따라 데이터셋 로딩 및 병합"""
    use_platform = os.environ.get("PLATFORM", "true").strip().lower() == "true"
    use_normal = os.environ.get("NORMAL", "true").strip().lower() == "true"

    datasets = []
    if use_platform:
        datasets.append(_load_json("platform_data.json"))
    if use_normal:
        datasets.append(_load_json("normal_data.json"))

    if not datasets:
        print("[WARNING] PLATFORM과 NORMAL이 모두 false — 데이터셋이 없습니다.")
        return {}

    result = datasets[0]
    for ds in datasets[1:]:
        result = _merge_data(result, ds)
    return result


# 모듈 로딩 시 한 번만 읽기
PROBE_DATA = _load_data()


@dataclass
class ProbeResult:
    """단일 프롬프트-응답 쌍의 스캔 결과"""
    probe_name: str
    category: str
    prompt: str
    response: Optional[str]
    is_vulnerable: bool
    detection_detail: str
    severity: str  # "취약", "양호"
    elapsed_time: float = 0.0
    gemini_detail: Optional[str] = None  # Gemini 2차 검증 결과


class BaseProbe:
    """모든 프로브의 기본 클래스"""

    name: str = "base"
    description: str = ""
    category: str = "unknown"
    severity: str = "취약"

    # 프롬프트 목록: 각 프로브가 정의
    prompts: List[str] = []

    # 트리거 키워드: 응답에 이 키워드가 포함되면 취약
    triggers: List[str] = []

    def __init__(self):
        """data.json에서 카테고리에 맞는 데이터 로딩"""
        if self.category in PROBE_DATA:
            data = PROBE_DATA[self.category]
            self.name = data.get("name", self.name)
            self.description = data.get("description", self.description)
            # severity는 더 이상 data.json에서 로딩하지 않음 (취약/양호 이진 판정)
            self.triggers = data.get("triggers", self.triggers)
            self.prompts = data.get("prompts", self.prompts)

    def get_prompts(self) -> List[str]:
        """프롬프트 목록 반환"""
        return self.prompts

    def _process_single(self, prompt, api_client, detector):
        """단일 프롬프트 처리 (스레드에서 실행)"""
        start_time = time.time()
        try:
            response = api_client.send(prompt)
        except Exception as e:
            response = f"[ERROR] {str(e)}"

        elapsed = time.time() - start_time

        is_vuln, detail = detector.analyze(
            prompt=prompt,
            response=response,
            triggers=self.triggers,
            category=self.category,
        )

        return ProbeResult(
            probe_name=self.name,
            category=self.category,
            prompt=prompt,
            response=response,
            is_vulnerable=is_vuln,
            detection_detail=detail,
            severity="취약" if is_vuln else "양호",
            elapsed_time=elapsed,
        )

    def run(self, api_client, detector, progress_callback=None, max_workers=None) -> List[ProbeResult]:
        """
        프로브 실행: 멀티스레드로 프롬프트를 API에 전송 후 탐지 결과 반환

        Args:
            api_client: API 호출 클라이언트
            detector: 응답 분석 디텍터
            progress_callback: 진행도 콜백 함수(current, total, result)
            max_workers: 동시 실행 스레드 수 (None이면 MAX_WORKERS 환경변수 사용, 기본 10)

        Returns:
            ProbeResult 리스트
        """
        if max_workers is None:
            max_workers = int(os.environ.get("MAX_WORKERS", "10"))
        prompts = self.get_prompts()
        total = len(prompts)

        # 결과를 인덱스 순으로 저장
        results = [None] * total
        lock = threading.Lock()
        completed = [0]  # mutable counter for closure

        def task(idx, prompt):
            result = self._process_single(prompt, api_client, detector)
            with lock:
                results[idx] = result
                completed[0] += 1
                if progress_callback:
                    progress_callback(completed[0], total, result)
            return result

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(task, idx, prompt): idx
                for idx, prompt in enumerate(prompts)
            }
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                print("\n\n⚠️  Ctrl+C 감지 — 스캔 중단 중...")
                for f in futures:
                    f.cancel()
                executor.shutdown(wait=False, cancel_futures=True)

        return [r for r in results if r is not None]

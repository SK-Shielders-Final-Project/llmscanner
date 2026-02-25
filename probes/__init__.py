"""
LLM 취약점 스캐너 — Probe 모듈

각 프로브는 BaseProbe를 상속하여 특정 취약점 카테고리의 프롬프트를 정의한다.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import time


@dataclass
class ProbeResult:
    """단일 프롬프트-응답 쌍의 스캔 결과"""
    probe_name: str
    category: str
    prompt: str
    response: Optional[str]
    is_vulnerable: bool
    detection_detail: str
    severity: str  # "HIGH", "MEDIUM", "LOW", "INFO"
    elapsed_time: float = 0.0


class BaseProbe:
    """모든 프로브의 기본 클래스"""

    name: str = "base"
    description: str = ""
    category: str = "unknown"
    severity: str = "MEDIUM"

    # 프롬프트 목록: 각 프로브가 정의
    prompts: List[str] = []

    # 트리거 키워드: 응답에 이 키워드가 포함되면 취약
    triggers: List[str] = []

    def get_prompts(self) -> List[str]:
        """프롬프트 목록 반환"""
        return self.prompts

    def run(self, api_client, detector, progress_callback=None) -> List[ProbeResult]:
        """
        프로브 실행: 모든 프롬프트를 API에 전송 후 탐지 결과 반환

        Args:
            api_client: API 호출 클라이언트
            detector: 응답 분석 디텍터
            progress_callback: 진행도 콜백 함수(current, total, result)

        Returns:
            ProbeResult 리스트
        """
        results = []
        prompts = self.get_prompts()
        total = len(prompts)

        for idx, prompt in enumerate(prompts, 1):
            start_time = time.time()
            try:
                response = api_client.send(prompt)
            except Exception as e:
                response = f"[ERROR] {str(e)}"

            elapsed = time.time() - start_time

            # 탐지 수행
            is_vuln, detail = detector.analyze(
                prompt=prompt,
                response=response,
                triggers=self.triggers,
                category=self.category,
            )

            result = ProbeResult(
                probe_name=self.name,
                category=self.category,
                prompt=prompt,
                response=response,
                is_vulnerable=is_vuln,
                detection_detail=detail,
                severity=self.severity if is_vuln else "INFO",
                elapsed_time=elapsed,
            )
            results.append(result)

            # 진행도 콜백 호출
            if progress_callback:
                progress_callback(idx, total, result)

        return results

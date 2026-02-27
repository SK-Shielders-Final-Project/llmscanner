"""
Vrompt — 스캔 엔진

프로브 로딩 → API 호출 → 탐지 → 평가 파이프라인을 실행하는 핵심 엔진.
"""

import os
import sys
import time
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init

from api_client import APIClient, DryRunClient
from detector import Detector
from probes import ProbeResult, BaseProbe
from probes.jailbreak import JailbreakProbe
from probes.unethical import UnethicalProbe
from probes.prompt_injection import PromptInjectionProbe
from probes.data_leakage import DataLeakageProbe
from probes.encoding import EncodingProbe
from probes.hallucination import HallucinationProbe
from probes.code_generation import CodeGenerationProbe
from probes.special_tokens import SpecialTokensProbe
from report import generate_report
from cross_verifier import verify_results

colorama_init(autoreset=True)

# ── 사용 가능한 프로브 레지스트리 ──
PROBE_REGISTRY = {
    "jailbreak": JailbreakProbe,
    "unethical": UnethicalProbe,
    "prompt_injection": PromptInjectionProbe,
    "data_leakage": DataLeakageProbe,
    "encoding": EncodingProbe,
    "hallucination": HallucinationProbe,
    "code_generation": CodeGenerationProbe,
    "special_tokens": SpecialTokensProbe,
}


class Scanner:
    """Vrompt 스캔 엔진"""

    def __init__(
        self,
        target_url: Optional[str] = None,
        probe_names: Optional[List[str]] = None,
        dry_run: bool = False,
        output_path: Optional[str] = None,
        delay: float = 1.0,
        timeout: int = 30,
        verify_ssl: bool = True,
        user_id: int = 1,
        jwt_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.target_url = target_url or APIClient.DEFAULT_URL
        self.dry_run = dry_run
        self.delay = delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # 리포트 저장 경로 (reports/ 폴더)
        if output_path:
            self.output_path = output_path
        else:
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            self.output_path = os.path.join(reports_dir, f"scan_report_{time.strftime('%Y%m%d_%H%M%S')}.md")

        # API 클라이언트 설정
        if dry_run:
            self.client = DryRunClient()
        else:
            self.client = APIClient(
                target_url=self.target_url,
                timeout=timeout,
                delay_between_requests=delay,
                verify_ssl=verify_ssl,
                user_id=user_id,
                jwt_token=jwt_token,
                username=username,
                password=password,
            )

        self.detector = Detector()

        # 프로브 로딩
        if probe_names:
            self.probes = []
            for name in probe_names:
                if name in PROBE_REGISTRY:
                    self.probes.append(PROBE_REGISTRY[name]())
                else:
                    print(f"{Fore.YELLOW}⚠ 알 수 없는 프로브: {name}{Style.RESET_ALL}")
        else:
            # 전체 프로브 로딩
            self.probes = [cls() for cls in PROBE_REGISTRY.values()]

    def run(self) -> List[ProbeResult]:
        """전체 스캔 실행"""
        all_results: List[ProbeResult] = []

        # 연결 확인 (dry-run이 아닌 경우)
        if not self.dry_run:
            self._check_connection()

        total_probes = len(self.probes)
        total_prompts = sum(len(p.get_prompts()) for p in self.probes)

        print(f"\n{Fore.CYAN}📋 스캔 계획{Style.RESET_ALL}")
        print(f"   프로브: {total_probes}개 카테고리")
        print(f"   프롬프트: {total_prompts}개")
        print(f"   대상: {self.target_url}")
        if self.dry_run:
            print(f"   모드: {Fore.YELLOW}🧪 DRY-RUN{Style.RESET_ALL}")
        print(f"\n{'═' * 70}\n")

        scan_start = time.time()

        completed_prompts = 0

        for probe_idx, probe in enumerate(self.probes, 1):
            prompts = probe.get_prompts()
            num_prompts = len(prompts)
            print(
                f"{Fore.CYAN}[{probe_idx}/{total_probes}] "
                f"{Style.BRIGHT}{probe.name}{Style.RESET_ALL}"
                f"  {probe.description}  ({num_prompts}개 프롬프트)"
            )

            # 프로브 실행 (진행도 콜백 포함)
            def progress_callback(current, total, result):
                nonlocal completed_prompts
                completed_prompts += 1
                overall_pct = completed_prompts / total_prompts * 100
                # 상태 아이콘
                icon = f"{Fore.RED}✗{Style.RESET_ALL}" if result.is_vulnerable else f"{Fore.GREEN}✓{Style.RESET_ALL}"
                # 프로그레스 바 (20칸)
                bar_len = 20
                filled = int(bar_len * current / total)
                bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_len - filled)}{Style.RESET_ALL}"
                # 현재 프롬프트 미리보기 (25자)
                prompt_preview = result.prompt[:25].replace('\n', ' ')
                print(
                    f"\r   {bar} {current}/{total} "
                    f"({overall_pct:5.1f}%) {icon} {prompt_preview}..."
                    f"{'':20}",
                    end="", flush=True
                )

            try:
                results = probe.run(self.client, self.detector, progress_callback=progress_callback, max_workers=5)
            except KeyboardInterrupt:
                print(f"\n\n{Fore.YELLOW}⚠️  Ctrl+C 감지 — 스캔 중단{Style.RESET_ALL}")
                break
            all_results.extend(results)
            print()  # 프로그레스 바 줄바꿈

            # 결과 요약 출력
            vuln_count = sum(1 for r in results if r.is_vulnerable)
            safe_count = len(results) - vuln_count

            if vuln_count > 0:
                print(
                    f"   {Fore.RED}✗ 취약: {vuln_count}개{Style.RESET_ALL}  "
                    f"{Fore.GREEN}✓ 안전: {safe_count}개{Style.RESET_ALL}"
                )
                # 취약점 상세 출력 (최대 3개)
                vuln_results = [r for r in results if r.is_vulnerable]
                for vr in vuln_results[:3]:
                    prompt_short = vr.prompt[:80].replace('\n', ' ')
                    print(f"   {Fore.RED}  └─ {vr.detection_detail}{Style.RESET_ALL}")
                    print(f"      프롬프트: {prompt_short}...")
                if len(vuln_results) > 3:
                    print(f"      ... 외 {len(vuln_results) - 3}건")
            else:
                print(f"   {Fore.GREEN}✓ 모두 안전 ({safe_count}개){Style.RESET_ALL}")

            print()

        scan_elapsed = time.time() - scan_start

        # ── LLM 교차 검증 (OpenRouter) ──
        if not self.dry_run:
            all_results = verify_results(all_results)

        # ── 최종 요약 ──
        print(f"\n{'═' * 70}")
        self._print_summary(all_results, scan_elapsed)

        # ── 리포트 저장 ──
        total_elapsed = time.time() - scan_start
        report = generate_report(
            results=all_results,
            target_url=self.target_url,
            output_path=self.output_path,
            dry_run=self.dry_run,
            elapsed_time=total_elapsed,
        )
        print(f"\n{Fore.CYAN}📄 리포트 저장: {Style.BRIGHT}{self.output_path}{Style.RESET_ALL}")

        return all_results


    def _check_connection(self):
        """API 연결 확인"""
        print(f"{Fore.CYAN}🔌 API 연결 확인 중... {Style.RESET_ALL}", end="", flush=True)
        success, detail = self.client.health_check()
        if success:
            print(f"{Fore.GREEN}✓ {detail}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠ {detail}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  계속 진행하시겠습니까? (y/n){Style.RESET_ALL}", end=" ")
            choice = input().strip().lower()
            if choice != 'y':
                print("스캔을 종료합니다.")
                sys.exit(1)

    def _print_summary(self, results: List[ProbeResult], elapsed: float):
        """최종 요약 출력"""
        total = len(results)
        pending_count = sum(1 for r in results if r.gemini_detail and "최종: 보류" in r.gemini_detail)
        # 보류 항목은 취약/양호에서 제외
        non_pending = [r for r in results if not (r.gemini_detail and "최종: 보류" in r.gemini_detail)]
        vuln_count = sum(1 for r in non_pending if r.is_vulnerable)
        safe_count = len(non_pending) - vuln_count

        print(f"\n{Style.BRIGHT}📊 스캔 완료 요약{Style.RESET_ALL}\n")
        print(f"   총 프롬프트:  {total}")
        print(f"   소요 시간:    {elapsed:.1f}초")

        if vuln_count > 0 or pending_count > 0:
            if vuln_count > 0:
                vuln_rate = vuln_count / total * 100
                print(f"   {Fore.RED}🔴 취약: {vuln_count}건 ({vuln_rate:.1f}%){Style.RESET_ALL}")
            if pending_count > 0:
                print(f"   {Fore.YELLOW}🟡 보류: {pending_count}건{Style.RESET_ALL}")
            print(f"   {Fore.GREEN}🟢 양호: {safe_count}건{Style.RESET_ALL}")
        else:
            print(f"   {Fore.GREEN}✓ 취약점 없음{Style.RESET_ALL}")

import os
import time
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from dotenv import load_dotenv

from modA_verifier import verify_modA, MODEL_A
from modB_verifier import verify_modB, MODEL_B


# ── .env 로딩 ──
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")


def _verify_one(r, category):
    """단일 결과에 대해 두 모델 호출 (스레드에서 실행)"""
    verdict_a = verify_modA(r.prompt, r.response, category)
    verdict_b = verify_modB(r.prompt, r.response, category)
    return verdict_a, verdict_b


def verify_results(results: List, delay: float = 0.0) -> List:
    """
    모든 프롬프트-응답 쌍을 두 LLM으로 교차 검증 (멀티스레드).

    Args:
        results: ProbeResult 리스트
        delay: 요청 간 딜레이 (초) - 유료 API이므로 기본 0

    Returns:
        보정된 ProbeResult 리스트 (원본 수정)
    """
    if not OPENROUTER_API_KEY:
        print(f"{Fore.YELLOW}⚠ OPENROUTER_API_KEY가 설정되지 않았습니다. 교차 검증을 건너뜁니다.{Style.RESET_ALL}")
        return results

    if not results:
        return results

    total = len(results)
    max_workers = 5

    print(f"\n{'═' * 70}")
    print(f"\n{Fore.CYAN}{Style.BRIGHT}🤖 LLM 교차 검증 시작{Style.RESET_ALL}")
    print(f"   모델 A: {MODEL_A}")
    print(f"   모델 B: {MODEL_B}")
    print(f"   검증 대상: {total}건 (전체 프롬프트)")
    print(f"   스레드: {max_workers}개\n")

    pending = 0
    confirmed_vuln = 0
    confirmed_safe = 0
    verify_start = time.time()
    done_count = 0

    # 멀티스레드로 교차 검증 실행
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {}
        for idx, r in enumerate(results):
            future = executor.submit(_verify_one, r, r.category)
            future_map[future] = idx

        try:
            for future in as_completed(future_map):
                idx = future_map[future]
                r = results[idx]
                done_count += 1

                # 프로그레스
                bar_len = 20
                filled = int(bar_len * done_count / total)
                bar = f"{Fore.MAGENTA}{'█' * filled}{Fore.WHITE}{'░' * (bar_len - filled)}{Style.RESET_ALL}"
                pct = done_count / total * 100
                prompt_preview = r.prompt[:30].replace('\n', ' ')
                print(
                    f"\r   {bar} {done_count}/{total} ({pct:5.1f}%) "
                    f"🔍 {prompt_preview}...{'':10}",
                    end="", flush=True
                )

                try:
                    verdict_a, verdict_b = future.result()
                except Exception as e:
                    verdict_a = {"result": "오류", "reason": str(e)[:80]}
                    verdict_b = {"result": "오류", "reason": str(e)[:80]}

                result_a = verdict_a["result"]
                result_b = verdict_b["result"]

                # 교차 검증 로직
                if result_a == "양호" and result_b == "양호":
                    final = "양호"
                    r.is_vulnerable = False
                    r.severity = "양호"
                    confirmed_safe += 1
                elif result_a == "취약" and result_b == "취약":
                    final = "취약"
                    r.is_vulnerable = True
                    r.severity = "취약"
                    confirmed_vuln += 1
                else:
                    final = "보류"
                    pending += 1

                # 두 모델의 결과를 gemini_detail에 저장
                model_a_short = MODEL_A.split("/")[-1]
                model_b_short = MODEL_B.split("/")[-1]
                r.gemini_detail = (
                    f"**최종: {final}**\n"
                    f"> 🅰️ {model_a_short}: [{verdict_a['result']} | {verdict_a.get('score', 0.0):.2f}점] {verdict_a['reason']}\n"
                    f"> 🅱️ {model_b_short}: [{verdict_b['result']} | {verdict_b.get('score', 0.0):.2f}점] {verdict_b['reason']}"
                )
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}⚠️  Ctrl+C 감지 — 교차 검증 중단 중...{Style.RESET_ALL}")
            for f in future_map:
                f.cancel()
            executor.shutdown(wait=False, cancel_futures=True)

    verify_elapsed = time.time() - verify_start
    print()  # 줄바꿈
    print(f"\n{Style.BRIGHT}📊 LLM 교차 검증 완료{Style.RESET_ALL}")
    print(f"   검증 수:     {total}건")
    print(f"   소요 시간:   {verify_elapsed:.1f}초")
    print(f"   {Fore.GREEN}✓ 양호:   {confirmed_safe}건{Style.RESET_ALL}")
    print(f"   {Fore.RED}✗ 취약:   {confirmed_vuln}건{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}⏸ 보류:   {pending}건{Style.RESET_ALL}")

    return results

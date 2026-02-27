"""
Vrompt — 리포트 생성기

스캔 결과를 마크다운 형식으로 출력 및 저장.
모든 프롬프트-응답 쌍을 가시적으로 표시.
"""

import os
from datetime import datetime
from typing import List, Dict
from probes import ProbeResult


def generate_report(
    results: List[ProbeResult],
    target_url: str,
    output_path: str = None,
    dry_run: bool = False,
    elapsed_time: float = 0.0,
) -> str:
    """
    스캔 결과를 마크다운 리포트로 생성.

    Args:
        results: 모든 프로브의 ProbeResult 리스트
        target_url: 스캔 대상 URL
        output_path: 리포트 저장 경로 (None이면 저장하지 않음)
        dry_run: 드라이런 여부

    Returns:
        마크다운 형식의 리포트 문자열
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── 통계 집계 ──
    total = len(results)
    vulns = [r for r in results if r.is_vulnerable and not (r.gemini_detail and "최종: 보류" in r.gemini_detail)]
    pending = [r for r in results if r.gemini_detail and "최종: 보류" in r.gemini_detail]
    safe = total - len(vulns) - len(pending)

    # 카테고리별 집계
    categories: Dict[str, Dict] = {}
    for r in results:
        if r.category not in categories:
            categories[r.category] = {"total": 0, "vulnerable": 0, "pending": 0, "safe": 0, "results": []}
        categories[r.category]["total"] += 1
        
        is_pending = bool(r.gemini_detail and "최종: 보류" in r.gemini_detail)
        
        if is_pending:
            categories[r.category]["pending"] += 1
        elif r.is_vulnerable:
            categories[r.category]["vulnerable"] += 1
        else:
            categories[r.category]["safe"] += 1
            
        categories[r.category]["results"].append(r)

    # ── 리포트 생성 ──
    lines = []
    lines.append("# 🔍 Vrompt 스캔 리포트\n")
    lines.append(f"> **스캔 일시**: {now}  ")
    lines.append(f"> **대상 URL**: `{target_url}`  ")
    if dry_run:
        lines.append("> **모드**: 🧪 DRY-RUN (실제 API 호출 없음)  ")
    if elapsed_time > 0:
        lines.append(f"> **총 소요 시간**: {elapsed_time:.1f}초  ")
    lines.append("")

    lines.append("---\n")

    # ── 전체 요약 ──
    lines.append("## 📊 전체 요약\n")
    lines.append(f"| 항목 | 값 |")
    lines.append(f"|------|-----|")
    lines.append(f"| 총 프롬프트 수 | {total} |")
    lines.append(f"| 🔴 취약점 발견 | **{len(vulns)}** |")
    lines.append(f"| 🟡 판정 보류 | {len(pending)} |")
    lines.append(f"| 🟢 안전 | {safe} |")
    
    # 보류를 제외하고 확정된 건수 기준으로 취약 비율 산출
    determined_total = total - len(pending)
    vuln_rate = (len(vulns) / determined_total * 100) if determined_total > 0 else 0
    lines.append(f"| 확정 취약률 | **{vuln_rate:.1f}%** |")
    lines.append("")

    lines.append("---\n")

    # ── 카테고리별 전체 결과 (프롬프트 + 응답 포함) ──
    lines.append("## 📋 카테고리별 상세 결과\n")

    CATEGORY_NAMES = {
        "jailbreak": "🔓 탈옥 (Jailbreak)",
        "unethical": "⚠️ 비윤리적 발언",
        "prompt_injection": "💉 프롬프트 인젝션",
        "data_leakage": "📤 데이터 유출",
        "encoding": "🔢 인코딩 우회",
        "hallucination": "👻 환각/허위정보",
        "code_generation": "💻 악성 코드 생성",
        "special_tokens": "🔤 특수 토큰 공격",
    }

    for cat_key, cat_data in categories.items():
        cat_name = CATEGORY_NAMES.get(cat_key, cat_key)
        cat_vuln = cat_data["vulnerable"]
        cat_pending = cat_data["pending"]
        cat_safe = cat_data["safe"]
        cat_total = cat_data["total"]
        
        cat_determined = cat_total - cat_pending
        cat_rate = (cat_vuln / cat_determined * 100) if cat_determined > 0 else 0

        if cat_vuln > 0:
            status_badge = f"🔴 **취약 ({cat_vuln}건 발견)**"
        elif cat_pending > 0:
            status_badge = f"🟡 **보류 ({cat_pending}건)**"
        else:
            status_badge = "🟢 **안전**"

        lines.append(f"### {cat_name}\n")
        lines.append(f"| 결과 | 전체 | 취약 | 보류 | 안전 | 확정 취약률 |")
        lines.append(f"|------|------|------|------|------|-------------|")
        lines.append(f"| {status_badge} | {cat_total} | {cat_vuln} | {cat_pending} | {cat_safe} | {cat_rate:.0f}% |")
        lines.append("")

        # ── 모든 프롬프트-응답 테이블 ──
        lines.append("<details>")
        lines.append(f"<summary>📝 전체 프롬프트-응답 ({cat_total}건)</summary>\n")

        for i, r in enumerate(cat_data["results"], 1):
            # 상태 아이콘 (취약/양호/보류 3원 판정)
            if r.gemini_detail and "최종: 보류" in r.gemini_detail:
                status_line = f"**🟡 #{i} — ⏸️ 보류**"
            elif r.is_vulnerable:
                status_line = f"**🔴 #{i} — ❌ 취약**"
            else:
                status_line = f"**🟢 #{i} — ✅ 양호**"

            lines.append(f"#### {status_line}\n")

            # 프롬프트
            prompt_display = r.prompt if len(r.prompt) <= 500 else r.prompt[:500] + "..."
            lines.append("**📨 프롬프트:**")
            lines.append("````")
            lines.append(prompt_display)
            lines.append("````\n")

            # 응답 — 내부 백틱(```) 이스케이프 처리
            resp_text = r.response or "(응답 없음)"
            resp_display = resp_text if len(resp_text) <= 800 else resp_text[:800] + "..."
            # 4+ 연속 백틱을 제거하여 코드 펜스 깨짐 방지
            resp_display = resp_display.replace("````", "'''")
            resp_display = resp_display.replace("```", "'''")
            lines.append("**💬 응답:**")
            lines.append("````")
            lines.append(resp_display)
            lines.append("````\n")

            # 1차 탐지 및 AI 교차 검증
            if r.is_vulnerable:
                lines.append(f"> ⚠️ **1차 탐지**: {r.detection_detail}  ")
            else:
                lines.append(f"> ✅ **1차 판정**: {r.detection_detail}  ")

            if r.gemini_detail:
                lines.append(f"> 🤖 **AI 교차 검증**:  ")
                for line in r.gemini_detail.split('\n'):
                    lines.append(f"> {line}  ")

            lines.append(f"> **응답 시간**: {r.elapsed_time:.2f}초\n")

            lines.append("---\n")

        lines.append("</details>\n")
        lines.append("")

    lines.append("---\n")

    # ── 취약점 요약 테이블 (취약점이 있을 때) ──
    if vulns:
        lines.append("## 🚨 발견된 취약점 요약\n")
        lines.append("| # | 카테고리 | 판정 | 탐지 사유 | 프롬프트 (요약) |")
        lines.append("|---|----------|------|-----------|----------------|")
        for i, r in enumerate(vulns, 1):
            cat_display = CATEGORY_NAMES.get(r.category, r.category)
            prompt_short = r.prompt[:60].replace("|", "\\|").replace("\n", " ")
            if len(r.prompt) > 60:
                prompt_short += "..."
            detail_short = (r.detection_detail or "")[:50]
            lines.append(f"| {i} | {cat_display} | 🔴 취약 | {detail_short} | {prompt_short} |")
        lines.append("")
        lines.append("---\n")

    # ── 권고사항 ──
    lines.append("## 🛡️ 권고사항\n")
    if len(vulns) > 0:
        lines.append("취약점이 발견되었습니다. 다음 조치를 권고합니다:\n")
        lines.append("1. **[긴급]** 발견된 취약점에 대한 즉시 패치 적용")
        lines.append("2. 시스템 프롬프트에 명시적 거부 지침 강화")
        lines.append("3. 입력 필터링 및 출력 검증 레이어 추가")
        lines.append("4. 인코딩된 입력에 대한 사전 디코딩 + 필터링 적용")
        lines.append("5. 정기적인 취약점 스캔 수행")
    else:
        lines.append("현재 스캔 기준으로 취약점이 발견되지 않았습니다. ✅")
        lines.append("정기적인 스캔을 통해 지속적인 모니터링을 권장합니다.")

    lines.append(f"\n---\n*Generated by Vrompt at {now}*\n")

    report = "\n".join(lines)

    # 파일 저장
    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    return report

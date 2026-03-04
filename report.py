"""
Vrompt — 리포트 생성기

스캔 결과를 마크다운 형식으로 출력 및 저장.
프롬프트 수가 많을 경우 여러 파일로 분할 저장.
"""

import os
from datetime import datetime
from typing import List, Dict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from probes import ProbeResult

# ── 한글 폰트 설정 ──
_FONT_CANDIDATES = ['Malgun Gothic', 'NanumGothic', 'AppleGothic', 'DejaVu Sans']
for _fname in _FONT_CANDIDATES:
    if any(_fname.lower() in f.name.lower() for f in fm.fontManager.ttflist):
        plt.rcParams['font.family'] = _fname
        break
plt.rcParams['axes.unicode_minus'] = False

# ── 파일당 최대 프롬프트 수 ──
CHUNK_SIZE = 200

CATEGORY_NAMES = {
    "jailbreak": "🔓 탈옥 (Jailbreak)",
    "unethical": "⚠️ 비윤리적 발언",
    "prompt_injection": "💉 프롬프트 인젝션",
    "data_leakage": "📤 데이터 유출",
    "encoding": "🔢 인코딩 우회",
    "hallucination": "👻 환각/허위정보",
    "code_generation": "💻 악성 코드 생성",
    "special_tokens": "🔤 특수 토큰 공격",
    "web_vulnerability": "🌐 웹 취약점",
}


def generate_report(
    results: List[ProbeResult],
    target_url: str,
    output_path: str = None,
    dry_run: bool = False,
    elapsed_time: float = 0.0,
) -> str:
    """
    스캔 결과를 마크다운 리포트로 생성.
    프롬프트 수가 CHUNK_SIZE 이하이면 단일 파일,
    초과하면 -1, -2, ... 형태로 분할 저장.

    Returns:
        첫 번째(또는 유일한) 리포트의 마크다운 문자열
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

    # ── 파일 분할 수 계산 ──
    total_chunks = max(1, (total + CHUNK_SIZE - 1) // CHUNK_SIZE)
    need_split = total_chunks > 1

    # ── 결과를 순서대로 flat list로 만들기 (카테고리 순서 유지) ──
    flat_results: List[ProbeResult] = []
    for cat_data in categories.values():
        flat_results.extend(cat_data["results"])

    # ── 요약부 생성 (첫 파일에 포함) ──
    summary_lines = _build_summary(
        now, target_url, dry_run, elapsed_time,
        total, vulns, pending, safe,
        categories, output_path, total_chunks,
    )

    # ── 분할 없이 단일 파일 ──
    if not need_split:
        detail_lines = _build_detail_section(categories, 0, total)
        footer_lines = _build_footer(vulns, now)
        all_lines = summary_lines + detail_lines + footer_lines
        report = "\n".join(all_lines)

        if output_path:
            _save_file(output_path, report)

        return report

    # ── 분할 저장 ──
    # 출력 경로에서 base 추출 (예: scan_report_20260304_093000)
    if output_path:
        dir_name = os.path.dirname(output_path)
        base_name = os.path.splitext(os.path.basename(output_path))[0]  # scan_report_xxx
        ext = os.path.splitext(output_path)[1]  # .md

    first_report = None
    global_prompt_idx = 0  # 전체 기준 프롬프트 인덱스

    for chunk_idx in range(total_chunks):
        chunk_start = chunk_idx * CHUNK_SIZE
        chunk_end = min(chunk_start + CHUNK_SIZE, total)
        chunk_num = chunk_idx + 1

        chunk_lines = []

        if chunk_idx == 0:
            # 첫 파일: 요약 + 상세(일부)
            chunk_lines.extend(summary_lines)
        else:
            # 후속 파일: 간단한 헤더
            chunk_lines.append(f"# 🔍 Vrompt 스캔 리포트 — Part {chunk_num}/{total_chunks}\n")
            chunk_lines.append(f"> **스캔 일시**: {now}  ")
            chunk_lines.append(f"> **대상 URL**: `{target_url}`  ")
            chunk_lines.append(f"> **파트**: {chunk_num} / {total_chunks}  (프롬프트 #{chunk_start + 1} ~ #{chunk_end})")
            chunk_lines.append("")
            chunk_lines.append("---\n")

        # 상세 결과 (해당 chunk)
        detail_lines = _build_detail_section_chunked(
            categories, chunk_start, chunk_end, total, chunk_num, total_chunks,
        )
        chunk_lines.extend(detail_lines)

        # 마지막 chunk에 취약점 요약/권고사항 추가
        if chunk_idx == total_chunks - 1:
            footer_lines = _build_footer(vulns, now)
            chunk_lines.extend(footer_lines)
        else:
            # 다음 파트 안내
            next_file = f"{base_name}-{chunk_num + 1}{ext}" if output_path else ""
            chunk_lines.append("---\n")
            chunk_lines.append(f"➡️ **다음 파트**: [{next_file}]({next_file})\n")

        report_text = "\n".join(chunk_lines)

        if chunk_idx == 0:
            first_report = report_text

        # 파일 저장
        if output_path:
            chunk_path = os.path.join(dir_name, f"{base_name}-{chunk_num}{ext}")
            _save_file(chunk_path, report_text)

    return first_report


def _build_summary(
    now, target_url, dry_run, elapsed_time,
    total, vulns, pending, safe,
    categories, output_path, total_chunks,
):
    """요약부 (전체 통계, 그래프, 카테고리 요약 테이블)"""
    lines = []
    lines.append("# 🔍 Vrompt 스캔 리포트\n")
    lines.append(f"> **스캔 일시**: {now}  ")
    lines.append(f"> **대상 URL**: `{target_url}`  ")
    if dry_run:
        lines.append("> **모드**: 🧪 DRY-RUN (실제 API 호출 없음)  ")
    if elapsed_time > 0:
        lines.append(f"> **총 소요 시간**: {elapsed_time:.1f}초  ")
    if total_chunks > 1:
        lines.append(f"> **리포트 파일 수**: {total_chunks}개 (파일당 최대 {CHUNK_SIZE}개 프롬프트)  ")
    lines.append("")

    lines.append("---\n")

    # ── 전체 요약 ──
    lines.append("## 📊 전체 요약\n")
    lines.append("| 항목 | 값 |")
    lines.append("|------|-----|")
    lines.append(f"| 총 프롬프트 수 | {total} |")
    lines.append(f"| 🔴 취약점 발견 | **{len(vulns)}** |")
    lines.append(f"| 🟡 판정 보류 | {len(pending)} |")
    lines.append(f"| 🟢 안전 | {safe} |")

    determined_total = total - len(pending)
    vuln_rate = (len(vulns) / determined_total * 100) if determined_total > 0 else 0
    lines.append(f"| 확정 취약률 | **{vuln_rate:.1f}%** |")
    lines.append("")

    # ── 그래프 생성 ──
    if output_path and total > 0:
        chart_dir = os.path.dirname(output_path)
        base_name = os.path.splitext(os.path.basename(output_path))[0]
        # 분할 시에도 차트 이름은 원래 base 사용
        chart_base = base_name.replace("-1", "")

        pie_path = os.path.join(chart_dir, f"{chart_base}_pie.png")
        _generate_pie_chart(len(vulns), len(pending), safe, pie_path)
        lines.append(f"![전체 판정 분포]({chart_base}_pie.png)\n")

        bar_path = os.path.join(chart_dir, f"{chart_base}_bar.png")
        _generate_bar_chart(categories, CATEGORY_NAMES, bar_path)
        lines.append(f"![카테고리별 판정 분포]({chart_base}_bar.png)\n")

    lines.append("---\n")

    return lines


def _build_detail_section(categories, start, end):
    """단일 파일용: 모든 카테고리 상세 결과"""
    lines = []
    lines.append("## 📋 카테고리별 상세 결과\n")

    for cat_key, cat_data in categories.items():
        cat_lines = _render_category(cat_key, cat_data, cat_data["results"])
        lines.extend(cat_lines)

    return lines


def _build_detail_section_chunked(categories, chunk_start, chunk_end, total, chunk_num, total_chunks):
    """분할 파일용: 해당 chunk 범위의 상세 결과"""
    lines = []
    lines.append(f"## 📋 카테고리별 상세 결과 (Part {chunk_num}/{total_chunks}, 프롬프트 #{chunk_start + 1}~#{chunk_end})\n")

    # 전체 결과를 카테고리 순서로 flat list
    global_idx = 0
    for cat_key, cat_data in categories.items():
        cat_results_in_chunk = []
        cat_result_indices = []  # (카테고리 내 인덱스, 글로벌 인덱스)

        for local_i, r in enumerate(cat_data["results"]):
            if chunk_start <= global_idx < chunk_end:
                cat_results_in_chunk.append(r)
                cat_result_indices.append(local_i + 1)
            global_idx += 1

        if cat_results_in_chunk:
            cat_lines = _render_category_partial(
                cat_key, cat_data, cat_results_in_chunk, cat_result_indices,
            )
            lines.extend(cat_lines)

    return lines


def _render_category(cat_key, cat_data, results_list):
    """카테고리 전체를 렌더링"""
    lines = []
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
    lines.append("| 결과 | 전체 | 취약 | 보류 | 안전 | 확정 취약률 |")
    lines.append("|------|------|------|------|------|-------------|")
    lines.append(f"| {status_badge} | {cat_total} | {cat_vuln} | {cat_pending} | {cat_safe} | {cat_rate:.0f}% |")
    lines.append("")

    lines.append("<details>")
    lines.append(f"<summary>📝 전체 프롬프트-응답 ({cat_total}건)</summary>\n")

    for i, r in enumerate(results_list, 1):
        lines.extend(_render_result_item(i, r))

    lines.append("</details>\n")
    lines.append("")
    return lines


def _render_category_partial(cat_key, cat_data, results_list, indices):
    """카테고리의 일부 결과만 렌더링 (분할용)"""
    lines = []
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
    lines.append("| 결과 | 전체 | 취약 | 보류 | 안전 | 확정 취약률 |")
    lines.append("|------|------|------|------|------|-------------|")
    lines.append(f"| {status_badge} | {cat_total} | {cat_vuln} | {cat_pending} | {cat_safe} | {cat_rate:.0f}% |")
    lines.append("")

    lines.append("<details>")
    lines.append(f"<summary>📝 프롬프트-응답 ({len(results_list)}건, #{indices[0]}~#{indices[-1]} of {cat_total})</summary>\n")

    for idx, r in zip(indices, results_list):
        lines.extend(_render_result_item(idx, r))

    lines.append("</details>\n")
    lines.append("")
    return lines


def _render_result_item(i, r):
    """개별 프롬프트-응답 항목 렌더링"""
    lines = []
    if r.gemini_detail and "최종: 보류" in r.gemini_detail:
        status_line = f"**🟡 #{i} — ⏸️ 보류**"
    elif r.is_vulnerable:
        status_line = f"**🔴 #{i} — ❌ 취약**"
    else:
        status_line = f"**🟢 #{i} — ✅ 양호**"

    lines.append(f"#### {status_line}\n")

    prompt_display = r.prompt if len(r.prompt) <= 500 else r.prompt[:500] + "..."
    lines.append("**📨 프롬프트:**")
    lines.append("````")
    lines.append(prompt_display)
    lines.append("````\n")

    resp_text = r.response or "(응답 없음)"
    resp_display = resp_text if len(resp_text) <= 800 else resp_text[:800] + "..."
    resp_display = resp_display.replace("````", "'''")
    resp_display = resp_display.replace("```", "'''")
    lines.append("**💬 응답:**")
    lines.append("````")
    lines.append(resp_display)
    lines.append("````\n")

    if r.is_vulnerable:
        lines.append(f"> ⚠️ **1차 탐지**: {r.detection_detail}  ")
    else:
        lines.append(f"> ✅ **1차 판정**: {r.detection_detail}  ")

    if r.gemini_detail:
        lines.append("> 🤖 **AI 교차 검증**:  ")
        for line in r.gemini_detail.split('\n'):
            lines.append(f"> {line}  ")

    lines.append(f"> **응답 시간**: {r.elapsed_time:.2f}초\n")
    lines.append("---\n")
    return lines


def _build_footer(vulns, now):
    """취약점 요약 + 권고사항 (마지막 파일에 포함)"""
    lines = []
    lines.append("---\n")

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
    return lines


def _save_file(path, content):
    """파일 저장 헬퍼"""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _generate_pie_chart(vuln_count: int, pending_count: int, safe_count: int, save_path: str):
    """전체 판정 분포 파이 차트 생성"""
    labels, sizes, colors = [], [], []
    if vuln_count > 0:
        labels.append(f'취약 ({vuln_count})')
        sizes.append(vuln_count)
        colors.append('#e74c3c')
    if pending_count > 0:
        labels.append(f'보류 ({pending_count})')
        sizes.append(pending_count)
        colors.append('#f39c12')
    if safe_count > 0:
        labels.append(f'양호 ({safe_count})')
        sizes.append(safe_count)
        colors.append('#2ecc71')

    if not sizes:
        return

    fig, ax = plt.subplots(figsize=(6, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.1f%%',
        startangle=90, textprops={'fontsize': 11}
    )
    for at in autotexts:
        at.set_fontsize(12)
        at.set_fontweight('bold')
    ax.set_title('전체 판정 분포', fontsize=14, fontweight='bold', pad=15)
    fig.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close(fig)


def _generate_bar_chart(categories: dict, category_names: dict, save_path: str):
    """카테고리별 취약/보류/양호 수평 스택 바 차트 생성"""
    cat_labels = []
    vuln_vals, pending_vals, safe_vals = [], [], []

    for cat_key, cat_data in categories.items():
        short_name = category_names.get(cat_key, cat_key)
        # 이모지 제거 (차트 깨짐 방지)
        short_name = short_name.lstrip('🔓⚠️💉📤🔢👻💻🔤🌐 ')
        cat_labels.append(short_name)
        vuln_vals.append(cat_data['vulnerable'])
        pending_vals.append(cat_data['pending'])
        safe_vals.append(cat_data['safe'])

    fig, ax = plt.subplots(figsize=(10, max(3, len(cat_labels) * 0.6)))

    y_pos = range(len(cat_labels))
    bars_safe = ax.barh(y_pos, safe_vals, color='#2ecc71', label='양호', height=0.6)
    bars_pending = ax.barh(y_pos, pending_vals, left=safe_vals, color='#f39c12', label='보류', height=0.6)
    left_vuln = [s + p for s, p in zip(safe_vals, pending_vals)]
    bars_vuln = ax.barh(y_pos, vuln_vals, left=left_vuln, color='#e74c3c', label='취약', height=0.6)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(cat_labels, fontsize=10)
    ax.set_xlabel('프롬프트 수', fontsize=11)
    ax.set_title('카테고리별 판정 분포', fontsize=14, fontweight='bold', pad=15)
    ax.legend(loc='lower right', fontsize=10)
    ax.invert_yaxis()

    fig.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close(fig)

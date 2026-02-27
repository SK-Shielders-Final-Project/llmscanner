"""
Vrompt — LLM 취약점 스캐너 CLI

사용법:
  vrompt                             # 대화형 메뉴 실행
  vrompt --all                       # 직접 전체 스캔 실행 (비대화형)
  vrompt --dry-run --all             # API 호출 없이 전체 프롬프트 확인
"""

import argparse
import sys
import os
import getpass

# 현재 디렉토리를 sys.path에 추가 (모듈 import용)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init as colorama_init
from scanner import Scanner, PROBE_REGISTRY

colorama_init(autoreset=True)


# ═══════════════════════════════════════════════════════════════
# ASCII 로고
# ═══════════════════════════════════════════════════════════════
def print_logo():
    logo = f"""
{Fore.CYAN}{Style.BRIGHT}
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   {Fore.RED}██╗   ██╗{Fore.YELLOW}██████╗  {Fore.GREEN}██████╗ {Fore.CYAN}███╗   ███╗{Fore.MAGENTA}██████╗ {Fore.WHITE}████████╗{Fore.CYAN}      ║
  ║   {Fore.RED}██║   ██║{Fore.YELLOW}██╔══██╗{Fore.GREEN}██╔═══██╗{Fore.CYAN}████╗ ████║{Fore.MAGENTA}██╔══██╗{Fore.WHITE}╚══██╔══╝{Fore.CYAN}      ║
  ║   {Fore.RED}██║   ██║{Fore.YELLOW}██████╔╝{Fore.GREEN}██║   ██║{Fore.CYAN}██╔████╔██║{Fore.MAGENTA}██████╔╝{Fore.WHITE}   ██║   {Fore.CYAN}      ║
  ║   {Fore.RED}╚██╗ ██╔╝{Fore.YELLOW}██╔══██╗{Fore.GREEN}██║   ██║{Fore.CYAN}██║╚██╔╝██║{Fore.MAGENTA}██╔═══╝ {Fore.WHITE}   ██║   {Fore.CYAN}      ║
  ║   {Fore.RED} ╚████╔╝ {Fore.YELLOW}██║  ██║{Fore.GREEN}╚██████╔╝{Fore.CYAN}██║ ╚═╝ ██║{Fore.MAGENTA}██║     {Fore.WHITE}   ██║   {Fore.CYAN}      ║
  ║   {Fore.RED}  ╚═══╝  {Fore.YELLOW}╚═╝  ╚═╝{Fore.GREEN} ╚═════╝ {Fore.CYAN}╚═╝     ╚═╝{Fore.MAGENTA}╚═╝     {Fore.WHITE}   ╚═╝   {Fore.CYAN}      ║
  ║                                                               ║
  ║   {Fore.WHITE}LLM Vulnerability Scanner v1.0{Fore.CYAN}                              ║
  ║                                                               ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(logo)


# ═══════════════════════════════════════════════════════════════
# 대화형 메뉴
# ═══════════════════════════════════════════════════════════════

# 현재 설정 (메뉴에서 변경 가능)
_settings = {
    "target_url": "https://zdme.kro.kr/api/chat",
    "user_id": 1,
    "jwt_token": "",
    "username": "",
    "password": "",
    "delay": 1.0,
    "timeout": 120,
    "verify_ssl": True,
    "output": None,
}


def print_menu():
    """메인 메뉴 출력"""
    url_display = _settings["target_url"]
    auth_status = ""
    if _settings["jwt_token"]:
        auth_status = f"  {Fore.GREEN}🔑 JWT 인증됨{Style.RESET_ALL}"
    elif _settings["username"]:
        auth_status = f"  {Fore.YELLOW}👤 로그인 대기: {_settings['username']}{Style.RESET_ALL}"
    else:
        auth_status = f"  {Fore.RED}⚠ 인증 미설정{Style.RESET_ALL}"

    print(f"\n{Fore.CYAN}{'─' * 56}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}대상 URL:{Style.RESET_ALL} {Fore.WHITE}{url_display}{Style.RESET_ALL}")
    print(auth_status)
    print(f"{Fore.CYAN}{'─' * 56}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}1{Style.RESET_ALL}  🔍  전체 스캔         (모든 프로브 실행)")
    print(f"  {Fore.YELLOW}2{Style.RESET_ALL}  🎯  선택 스캔         (프로브 선택 실행)")
    print(f"  {Fore.YELLOW}3{Style.RESET_ALL}  🧪  드라이런          (API 호출 없이 프롬프트만 확인)")
    print(f"  {Fore.YELLOW}4{Style.RESET_ALL}  📋  프로브 목록       (사용 가능한 프로브 보기)")
    print(f"  {Fore.YELLOW}5{Style.RESET_ALL}  🔑  로그인            (JWT 토큰 획득)")
    print(f"  {Fore.YELLOW}6{Style.RESET_ALL}  ⚙️   설정 변경         (URL, 딜레이, 타임아웃 등)")
    print(f"  {Fore.YELLOW}0{Style.RESET_ALL}  🚪  종료")
    print(f"{Fore.CYAN}{'─' * 56}{Style.RESET_ALL}")


def list_probes():
    """프로브 목록 출력"""
    print(f"\n{Style.BRIGHT}📋 사용 가능한 프로브 목록{Style.RESET_ALL}\n")
    print(f"  {'번호':<6} {'이름':<20} {'프롬프트수':<10} 설명")
    print(f"  {'─' * 4}  {'─' * 20} {'─' * 10} {'─' * 35}")
    for i, (name, cls) in enumerate(PROBE_REGISTRY.items(), 1):
        probe = cls()
        prompt_count = len(probe.get_prompts())
        print(
            f"  {Fore.YELLOW}{i:<6}{Style.RESET_ALL}"
            f"{Fore.CYAN}{name:<20}{Style.RESET_ALL} "
            f"{prompt_count:<10} "
            f"{probe.description}"
        )
    print()


def select_probes_menu() -> list:
    """프로브 선택 메뉴"""
    probe_names = list(PROBE_REGISTRY.keys())

    print(f"\n{Style.BRIGHT}🎯 실행할 프로브를 선택하세요{Style.RESET_ALL}")
    print(f"   번호를 쉼표로 구분하여 입력 (예: 1,3,5)\n")

    for i, name in enumerate(probe_names, 1):
        probe = PROBE_REGISTRY[name]()
        prompt_count = len(probe.get_prompts())
        print(
            f"  {Fore.YELLOW}[{i}]{Style.RESET_ALL} "
            f"{Fore.CYAN}{name:<20}{Style.RESET_ALL} "
            f"({prompt_count}개)  {probe.description}"
        )

    print()
    try:
        choice = input(f"  {Fore.CYAN}선택 ▶ {Style.RESET_ALL}").strip()
        if not choice:
            return []

        indices = [int(x.strip()) for x in choice.split(",")]
        selected = []
        for idx in indices:
            if 1 <= idx <= len(probe_names):
                selected.append(probe_names[idx - 1])
            else:
                print(f"  {Fore.YELLOW}⚠ 잘못된 번호 무시: {idx}{Style.RESET_ALL}")

        if selected:
            print(f"\n  {Fore.GREEN}✓ 선택됨: {', '.join(selected)}{Style.RESET_ALL}")
        return selected
    except ValueError:
        print(f"  {Fore.RED}✗ 잘못된 입력입니다.{Style.RESET_ALL}")
        return []


def login_menu():
    """로그인 메뉴 — JWT 토큰 직접 입력 또는 ID/PW 로그인"""
    print(f"\n{Style.BRIGHT}🔑 인증 설정{Style.RESET_ALL}\n")
    print(f"  {Fore.YELLOW}1{Style.RESET_ALL}  ID/PW 로그인        (/api/user/auth/login)")
    print(f"  {Fore.YELLOW}2{Style.RESET_ALL}  JWT 토큰 직접 입력")
    print(f"  {Fore.YELLOW}0{Style.RESET_ALL}  ← 돌아가기")
    print()

    choice = input(f"  {Fore.CYAN}선택 ▶ {Style.RESET_ALL}").strip()

    if choice == "1":
        uname = input(f"  아이디: ").strip()
        pwd = getpass.getpass(f"  비밀번호: ")
        if not uname or not pwd:
            print(f"  {Fore.RED}✗ 아이디와 비밀번호를 모두 입력하세요{Style.RESET_ALL}")
            return

        _settings["username"] = uname
        _settings["password"] = pwd

        # 즉시 로그인 시도
        print(f"\n  {Fore.CYAN}🔌 로그인 중...{Style.RESET_ALL}", end=" ", flush=True)
        try:
            from api_client import APIClient
            client = APIClient(
                target_url=_settings["target_url"],
                verify_ssl=_settings["verify_ssl"],
                username=uname,
                password=pwd,
            )
            result = client.login()
            _settings["jwt_token"] = result.get("accessToken", "")
            _settings["user_id"] = result.get("userId", _settings["user_id"])
            print(f"{Fore.GREEN}✓ 로그인 성공!{Style.RESET_ALL}")
            print(f"  사용자 ID: {_settings['user_id']}")
            print(f"  토큰: {_settings['jwt_token'][:30]}...")
        except Exception as e:
            print(f"{Fore.RED}✗ 로그인 실패{Style.RESET_ALL}")
            print(f"  {Fore.RED}{str(e)}{Style.RESET_ALL}")

    elif choice == "2":
        token = input(f"  JWT 토큰: ").strip()
        _settings["jwt_token"] = token
        if token:
            print(f"  {Fore.GREEN}✓ JWT 토큰 설정됨 ({token[:20]}...){Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}✓ JWT 토큰 제거됨{Style.RESET_ALL}")


def settings_menu():
    """설정 변경 메뉴"""
    while True:
        token_display = (_settings['jwt_token'][:20] + '...' + _settings['jwt_token'][-10:]) if _settings['jwt_token'] else '(미설정)'
        print(f"\n{Style.BRIGHT}⚙️  현재 설정{Style.RESET_ALL}\n")
        print(f"  {Fore.YELLOW}1{Style.RESET_ALL}  대상 URL:     {Fore.WHITE}{_settings['target_url']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}2{Style.RESET_ALL}  사용자 ID:    {_settings['user_id']}")
        print(f"  {Fore.YELLOW}3{Style.RESET_ALL}  요청 딜레이:  {_settings['delay']}초")
        print(f"  {Fore.YELLOW}4{Style.RESET_ALL}  타임아웃:     {_settings['timeout']}초")
        print(f"  {Fore.YELLOW}5{Style.RESET_ALL}  SSL 검증:     {'✓ 활성' if _settings['verify_ssl'] else '✗ 비활성'}")
        print(f"  {Fore.YELLOW}6{Style.RESET_ALL}  리포트 경로:  {_settings['output'] or '(자동 생성)'}")
        print(f"  {Fore.YELLOW}0{Style.RESET_ALL}  ← 돌아가기")
        print()

        try:
            choice = input(f"  {Fore.CYAN}변경할 항목 ▶ {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "0" or choice == "":
            break
        elif choice == "1":
            url = input(f"  새 URL: ").strip()
            if url:
                _settings["target_url"] = url
                print(f"  {Fore.GREEN}✓ URL 변경됨{Style.RESET_ALL}")
        elif choice == "2":
            try:
                val = int(input(f"  새 사용자 ID: ").strip())
                _settings["user_id"] = val
                print(f"  {Fore.GREEN}✓ 사용자 ID 변경됨{Style.RESET_ALL}")
            except ValueError:
                print(f"  {Fore.RED}✗ 정수를 입력하세요{Style.RESET_ALL}")
        elif choice == "3":
            try:
                val = float(input(f"  새 딜레이 (초): ").strip())
                _settings["delay"] = val
                print(f"  {Fore.GREEN}✓ 딜레이 변경됨{Style.RESET_ALL}")
            except ValueError:
                print(f"  {Fore.RED}✗ 숫자를 입력하세요{Style.RESET_ALL}")
        elif choice == "4":
            try:
                val = int(input(f"  새 타임아웃 (초): ").strip())
                _settings["timeout"] = val
                print(f"  {Fore.GREEN}✓ 타임아웃 변경됨{Style.RESET_ALL}")
            except ValueError:
                print(f"  {Fore.RED}✗ 숫자를 입력하세요{Style.RESET_ALL}")
        elif choice == "5":
            _settings["verify_ssl"] = not _settings["verify_ssl"]
            status = "활성" if _settings["verify_ssl"] else "비활성"
            print(f"  {Fore.GREEN}✓ SSL 검증 {status}{Style.RESET_ALL}")
        elif choice == "6":
            path = input(f"  리포트 저장 경로 (빈 입력 = 자동): ").strip()
            _settings["output"] = path if path else None
            print(f"  {Fore.GREEN}✓ 리포트 경로 변경됨{Style.RESET_ALL}")


def run_scan(probe_names=None, dry_run=False):
    """스캔 실행"""
    # 인증 확인 (dry-run이 아닌 경우)
    if not dry_run and not _settings["jwt_token"] and not _settings["username"]:
        print(f"\n  {Fore.RED}⚠ 인증이 설정되지 않았습니다.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}  메뉴 5번 (로그인)에서 JWT 토큰 또는 ID/PW를 입력하세요.{Style.RESET_ALL}")
        return

    scanner = Scanner(
        target_url=_settings["target_url"],
        probe_names=probe_names,
        dry_run=dry_run,
        output_path=_settings["output"],
        delay=_settings["delay"],
        timeout=_settings["timeout"],
        verify_ssl=_settings["verify_ssl"],
        user_id=_settings["user_id"],
        jwt_token=_settings["jwt_token"] or None,
        username=_settings["username"] or None,
        password=_settings["password"] or None,
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠ 스캔이 사용자에 의해 중단되었습니다.{Style.RESET_ALL}")

    print()
    input(f"  {Fore.CYAN}[Enter] 메뉴로 돌아가기...{Style.RESET_ALL}")


def interactive_menu():
    """대화형 메뉴 루프"""
    print_logo()

    while True:
        print_menu()
        try:
            choice = input(f"  {Fore.CYAN}선택 ▶ {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Fore.YELLOW}👋 스캐너를 종료합니다.{Style.RESET_ALL}\n")
            break

        if choice == "1":
            # 전체 스캔
            run_scan(probe_names=None, dry_run=False)

        elif choice == "2":
            # 선택 스캔
            selected = select_probes_menu()
            if selected:
                run_scan(probe_names=selected, dry_run=False)
            else:
                print(f"  {Fore.YELLOW}⚠ 선택된 프로브가 없습니다.{Style.RESET_ALL}")

        elif choice == "3":
            # 드라이런
            print(f"\n  {Fore.YELLOW}🧪 드라이런 모드 — API 호출 없이 프롬프트만 확인{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}1{Style.RESET_ALL}  전체 프로브 드라이런")
            print(f"  {Fore.YELLOW}2{Style.RESET_ALL}  선택 프로브 드라이런")
            sub = input(f"  {Fore.CYAN}선택 ▶ {Style.RESET_ALL}").strip()
            if sub == "1":
                run_scan(probe_names=None, dry_run=True)
            elif sub == "2":
                selected = select_probes_menu()
                if selected:
                    run_scan(probe_names=selected, dry_run=True)

        elif choice == "4":
            list_probes()

        elif choice == "5":
            login_menu()

        elif choice == "6":
            settings_menu()

        elif choice == "0":
            print(f"\n{Fore.YELLOW}👋 스캐너를 종료합니다.{Style.RESET_ALL}\n")
            break

        else:
            print(f"  {Fore.RED}✗ 잘못된 선택입니다. 0~6 사이의 숫자를 입력하세요.{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════
# main — argparse는 비대화형 모드용으로 유지
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        prog="vrompt",
        description="Vrompt — LLM 취약점 스캐너 (Garak 기반 경량 스캔 도구)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
인자 없이 실행하면 대화형 메뉴가 표시됩니다.
비대화형 모드 예시:
  vrompt --all                          전체 스캔
  vrompt --probe jailbreak unethical    특정 카테고리만
  vrompt --dry-run --all                프롬프트만 확인
        """,
    )
    parser.add_argument("--target-url", type=str, default=None)
    parser.add_argument("--probe", nargs="+", type=str, default=None)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--no-ssl-verify", action="store_true")
    parser.add_argument("--list", action="store_true", dest="list_probes")
    parser.add_argument("--jwt-token", type=str, default=None)
    parser.add_argument("--username", type=str, default=None)
    parser.add_argument("--password", type=str, default=None)

    args = parser.parse_args()

    # ── 비대화형 모드 (인자가 지정된 경우) ──
    if args.list_probes:
        print_logo()
        list_probes()
        return

    if args.all or args.probe:
        if args.target_url:
            _settings["target_url"] = args.target_url
        _settings["delay"] = args.delay
        _settings["timeout"] = args.timeout
        _settings["verify_ssl"] = not args.no_ssl_verify
        _settings["output"] = args.output
        if args.jwt_token:
            _settings["jwt_token"] = args.jwt_token
        if args.username:
            _settings["username"] = args.username
        if args.password:
            _settings["password"] = args.password

        print_logo()
        run_scan(
            probe_names=args.probe if not args.all else None,
            dry_run=args.dry_run,
        )
        return

    # ── 인자 없음 → 대화형 메뉴 진입 ──
    interactive_menu()


if __name__ == "__main__":
    main()

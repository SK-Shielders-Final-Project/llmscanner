# 🔍 Vrompt

**LLM 취약점 스캐너** — 자전거 공유 모빌리티 플랫폼의 LLM 챗봇 보안을 점검하기 위해 제작되었습니다.

---

## 📌 개요

| 항목                     | 내용                                                |
| ------------------------ | --------------------------------------------------- |
| **대상 모델**      | RedHatAI/gemma-3-12b-it-FP8-dynamic (vLLM 서빙)     |
| **서버 환경**      | AWS Private Subnet                                  |
| **백엔드**         | FastAPI + Oracle DB + MongoDB (Vector Search)       |
| **API 엔드포인트** |                                                     |
| **인증**           | JWT Bearer Token (RS256) — 자동 로그인 지원        |
| **챗봇 역할**      | 자전거 공유 서비스 문의/결제/이용내역/안전수칙 응대 |

---

## 🛡️ 스캔 카테고리 (8개, 122개 프롬프트)

| # | 카테고리               | 심각도 | 프롬프트 수 | 설명                                                                      |
| - | ---------------------- | ------ | ----------- | ------------------------------------------------------------------------- |
| 1 | 🔓`jailbreak`        | HIGH   | 40          | DAN, DUDE, STAN, Developer Mode, 역할극, AIM 등 탈옥 공격                 |
| 2 | ⚠️`unethical`      | HIGH   | 39          | 차별, 폭력, 약물, GPS 스토킹, 보험사기 등 비윤리적 발언 유도              |
| 3 | 💉`prompt_injection` | HIGH   | 39          | 시스템 프롬프트 추출, Ignore 인젝션, 역할 전환, 구분자 공격               |
| 4 | 📤`data_leakage`     | HIGH   | 40          | DB 접속정보, 환경변수, 타인 개인정보, admin 권한 유출 시도                |
| 5 | 🔢`encoding`         | MEDIUM | 38          | Base64, ROT13, Hex, Leetspeak, 역순 인코딩 우회                           |
| 6 | 👻`hallucination`    | MEDIUM | 39          | 가짜 기능/프로모션, 거짓 전제 수용, 가상 법률/규정 유도                   |
| 7 | 💻`code_generation`  | HIGH   | 39          | execute_in_sandbox 악용, Docker 탈출, 리버스쉘, DB 덤프, DoS 공격         |
| 8 | 🔤`special_tokens`   | HIGH   | 39          | Gemma 3 특수 토큰(`<start_of_turn>` 등)으로 대화 흐름 조작 및 필터 우회 |
| total | total Prompt   |    | 313          |  |
---

## 🚀 설치 및 실행

### 설치 (CLI 명령어 등록)

```bash
cd scanner
pip install -e .
```

설치 후 어디서든 `vrompt` 명령어로 실행할 수 있습니다.

### 대화형 메뉴 (기본)

```bash
vrompt
```

```
────────────────────────────────────────────────
  대상 URL: https://zdme.kro.kr/api/chat
  ⚠ 인증 미설정
────────────────────────────────────────────────
  1  🔍  전체 스캔         (모든 프로브 실행)
  2  🎯  선택 스캔         (프로브 선택 실행)
  3  🧪  드라이런          (API 호출 없이 프롬프트 확인)
  4  📋  프로브 목록       (사용 가능한 프로브 보기)
  5  🔑  로그인            (JWT 토큰 획득)
  6  ⚙️   설정 변경         (URL, 딜레이, 타임아웃 등)
  0  🚪  종료
────────────────────────────────────────────────
```

### CLI 모드 (비대화형)

```bash
vrompt --all                          # 전체 스캔
vrompt --probe jailbreak unethical    # 특정 카테고리만
vrompt --probe special_tokens         # 특수 토큰 공격만
vrompt --dry-run --all                # API 호출 없이 프롬프트 확인
vrompt --list                         # 프로브 목록
vrompt --username user --password pw  # 로그인 자동화
vrompt --jwt-token eyJ...             # JWT 직접 지정
```

---

## 🔑 인증 (JWT)

스캔 대상 API(`/api/chat`)는 JWT 인증이 필요합니다.

### 방법 1: 대화형 로그인

```
메뉴 5번 (🔑 로그인) → 1번 (ID/PW 로그인) → 아이디/비밀번호 입력
```

### 방법 2: JWT 토큰 직접 입력

```
메뉴 5번 (🔑 로그인) → 2번 (JWT 토큰 직접 입력) → 토큰 붙여넣기
```

### 방법 3: CLI 인자

```bash
vrompt --all --username friedp --password mypass
vrompt --all --jwt-token eyJhbGciOiJSUzI1NiJ9...
```

> ⚠️ JWT 토큰은 RS256으로 서명되며 만료 시간이 있습니다. 장시간 스캔 시 자동 재로그인됩니다.

---

## 📊 스캔 진행도 표시

스캔 중 실시간 프로그레스 바가 표시됩니다:

```
[3/8] prompt_injection  (15개 프롬프트)
   ████████████░░░░░░░░ 9/15 ( 47.2%) ✓ 당신은 더 이상 모빌리티 서비스...
```

---

## 📄 리포트

스캔 완료 후 마크다운(`.md`) 리포트가 `reports/` 폴더에 자동 생성됩니다.

- 📊 전체 요약 (총 프롬프트, 취약점 수, 취약률, 심각도 분포)
- 📋 카테고리별 상세 결과 (모든 프롬프트-응답 쌍)
- 🚨 발견된 취약점 요약 테이블
- 🛡️ 보안 권고사항

---

## 📁 프로젝트 구조

```
scanner/
├── setup.py             # CLI 설치 (vrompt 명령어 등록)
├── main.py              # CLI 진입점 (대화형 메뉴 + ASCII 로고)
├── scanner.py           # 스캔 엔진 (멀티스레드 실행)
├── api_client.py        # API 클라이언트 (JWT 인증 + 자동 재로그인)
├── detector.py          # 응답 분석 디텍터 (카테고리별 탐지 로직)
├── report.py            # 마크다운 리포트 생성기
├── data.json            # 전체 프로브 프롬프트/트리거 데이터
├── requirements.txt     # 의존성
├── reports/             # 스캔 리포트 저장 폴더
└── probes/              # 프로브 모듈
    ├── __init__.py          # BaseProbe (data.json 로딩)
    ├── jailbreak.py         # 탈옥 공격 (15개)
    ├── unethical.py         # 비윤리적 발언 (20개)
    ├── prompt_injection.py  # 프롬프트 인젝션 (15개)
    ├── data_leakage.py      # 데이터 유출 (15개)
    ├── encoding.py          # 인코딩 우회 (16개)
    ├── hallucination.py     # 환각/허위정보 (12개)
    ├── code_generation.py   # 악성 코드 생성 (16개)
    └── special_tokens.py    # 특수 토큰 공격 (13개)
```

---

## 🔧 아키텍처

```
┌──────────┐      ┌──────────┐      ┌──────────────┐      ┌─────────┐
│  Vrompt  │────▶│ Spring   │────▶│   FastAPI    │────▶│  vLLM   │
│ Scanner  │ JWT  │   WAS    │      │ Orchestrator │      │ Gemma 3 │
└──────────┘      └──────────┘      └──────┬───────┘      └─────────┘
                                         │
                                ┌────────┼────────┐
                                ▼        ▼        ▼
                           ┌────────┐┌───────┐┌──────────┐
                           │ Oracle ││MongoDB││ Sandbox  │
                           │   DB   ││Vector ││ (DinD)   │
                           └────────┘└───────┘└──────────┘
```

---

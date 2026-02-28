"""
Vrompt — API 클라이언트

타겟 LLM 챗봇의 REST API와 통신하는 모듈.
Spring Boot 백엔드 기반 — JWT 인증 + /api/chat 엔드포인트

요청 형식:
  POST /api/chat
  Authorization: Bearer <accessToken>
  {
    "message": {
      "role": "user",
      "user_id": 1,
      "content": "사용자 메시지"
    }
  }

응답 형식:
  {
    "userId": 1,
    "assistantMessage": "모델 응답",
    "model": "RedHatAI/gemma-3-12b-it-FP8-dynamic"
  }

로그인:
  POST /api/user/auth/login
  {"username": "...", "password": "..."}
  → {"accessToken": "...", "refreshToken": "...", "userId": N}
"""

import json
import time
import requests
from typing import Optional


class APIClient:
    """타겟 LLM API 클라이언트 (Spring Boot 백엔드 대응)"""

    DEFAULT_URL = "https://zdme.kro.kr/api/chat"
    LOGIN_PATH = "/api/user/auth/login"

    def __init__(
        self,
        target_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 2,
        delay_between_requests: float = 1.0,
        verify_ssl: bool = True,
        user_id: int = 1,
        jwt_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.target_url = target_url or self.DEFAULT_URL
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay_between_requests
        self.verify_ssl = verify_ssl
        self.user_id = user_id
        self.jwt_token = jwt_token
        self.username = username
        self.password = password

        # 기본 URL 추출 (로그인용)
        # "https://zdme.kro.kr/api/chat" → "https://zdme.kro.kr"
        url_parts = self.target_url.split("/api/")
        self.base_url = url_parts[0] if len(url_parts) > 1 else self.target_url.rsplit("/", 1)[0]

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

        # JWT 토큰이 직접 제공된 경우 헤더에 설정
        if self.jwt_token:
            self.session.headers["Authorization"] = f"Bearer {self.jwt_token}"

        self._last_request_time = 0
        self.total_requests = 0
        self.failed_requests = 0

    # ── 로그인 ──────────────────────────────────────────────────
    def login(self, username: Optional[str] = None, password: Optional[str] = None) -> dict:
        """
        POST /api/user/auth/login 으로 JWT 토큰 획득.

        Returns:
            {"accessToken": "...", "refreshToken": "...", "userId": N}

        Raises:
            ConnectionError: 로그인 실패 시
        """
        uname = username or self.username
        pwd = password or self.password
        if not uname or not pwd:
            raise ValueError("로그인에 username과 password가 필요합니다.")

        login_url = f"{self.base_url}{self.LOGIN_PATH}"
        payload = json.dumps({"username": uname, "password": pwd}, ensure_ascii=False)

        try:
            resp = self.session.post(
                login_url,
                data=payload,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            data = resp.json()

            # 토큰 저장 및 헤더 갱신
            self.jwt_token = data.get("accessToken", "")
            self.user_id = data.get("userId", self.user_id)
            self.session.headers["Authorization"] = f"Bearer {self.jwt_token}"

            return data

        except requests.exceptions.HTTPError as e:
            raise ConnectionError(f"로그인 실패 (HTTP {resp.status_code}): {resp.text}")
        except Exception as e:
            raise ConnectionError(f"로그인 실패: {str(e)}")

    # ── 요청 간 딜레이 ─────────────────────────────────────────
    def _rate_limit(self):
        """요청 간 최소 딜레이 보장"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

    # ── 채팅 요청 ──────────────────────────────────────────────
    def send(self, message: str) -> str:
        """
        메시지를 /api/chat에 전송하고 assistantMessage를 반환.

        요청: {"message": {"role": "user", "user_id": N, "content": "..."}}
        응답: {"userId": N, "assistantMessage": "...", "model": "..."}
        """
        self._rate_limit()
        self.total_requests += 1

        payload = json.dumps({
            "message": {
                "role": "user",
                "user_id": self.user_id,
                "content": message,
            }
        }, ensure_ascii=False)

        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.post(
                    self.target_url,
                    data=payload,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                self._last_request_time = time.time()

                # 인증 실패 — 토큰 만료 가능성 또는 가드레일 차단
                if resp.status_code == 401 or resp.status_code == 403:
                    # 자동 재로그인 시도
                    if self.username and self.password:
                        try:
                            self.login()
                            continue  # 재시도
                        except Exception:
                            pass
                    last_error = f"인증 실패 (HTTP {resp.status_code}) — JWT 토큰을 확인하세요"
                    break

                if resp.status_code == 429:
                    wait = min(2 ** attempt, 30)
                    time.sleep(wait)
                    continue

                if resp.status_code >= 500:
                    wait = min(2 ** attempt, 30)
                    time.sleep(wait)
                    continue

                # 4xx 클라이언트 오류 발생 시 가드레일 메시지 검사
                if 400 <= resp.status_code < 500:
                    try:
                        error_body = resp.text
                        if "안전 정책에 따라" in error_body:
                            return "안전 정책에 따라 요청을 처리할 수 없습니다. 다른 방식으로 질문해 주세요."
                    except Exception:
                        pass

                resp.raise_for_status()

                # 응답 파싱 — assistantMessage 필드 우선
                try:
                    data = resp.json()
                    # 백엔드 ChatResponseDto 필드: assistantMessage
                    if "assistantMessage" in data:
                        return str(data["assistantMessage"])
                    # 기타 가능한 필드명 (범용 호환)
                    for field in ["response", "reply", "text", "message", "content", "answer", "output"]:
                        if field in data:
                            return str(data[field])
                    # 알려진 필드 없으면 전체를 문자열로
                    return json.dumps(data, ensure_ascii=False)
                except (json.JSONDecodeError, ValueError):
                    return resp.text

            except requests.exceptions.Timeout:
                last_error = f"Timeout after {self.timeout}s (attempt {attempt}/{self.max_retries})"
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection failed: {str(e)}"
            except requests.exceptions.HTTPError as e:
                last_error = f"HTTP {resp.status_code}: {str(e)}"
                break  # HTTP 4xx는 재시도 불필요

        self.failed_requests += 1
        raise ConnectionError(f"API 요청 실패: {last_error}")

    # ── 연결 확인 ────────────────────────────────────────────
    def health_check(self) -> tuple:
        """
        API 연결 상태 확인.
        Returns:
            (success: bool, detail: str)
        """
        # 1차: 간단한 요청으로 서버 연결만 확인 (빈 content 전송)
        try:
            payload = json.dumps({
                "message": {
                    "role": "user",
                    "user_id": self.user_id,
                    "content": "hi",
                }
            }, ensure_ascii=False)
            resp = self.session.post(
                self.target_url,
                data=payload,
                timeout=self.timeout,  # 전체 타임아웃 사용
                verify=self.verify_ssl,
            )
            if resp.status_code == 200:
                return True, "연결 성공"
            elif resp.status_code in (401, 403):
                return True, f"서버 연결됨 (인증 필요: HTTP {resp.status_code})"
            else:
                return False, f"HTTP {resp.status_code}: {resp.text[:100]}"
        except requests.exceptions.Timeout:
            return False, f"Timeout ({self.timeout}초 초과) — LLM 응답이 느릴 수 있습니다"
        except requests.exceptions.ConnectionError as e:
            return False, f"연결 실패: {str(e)[:100]}"
        except Exception as e:
            return False, f"오류: {str(e)[:100]}"


class DryRunClient:
    """API 호출 없이 프롬프트만 확인하는 테스트용 클라이언트"""

    def __init__(self):
        self.total_requests = 0
        self.failed_requests = 0

    def send(self, message: str) -> str:
        self.total_requests += 1
        return "[DRY-RUN] 실제 API 호출 없음 — 프롬프트만 표시"

    def health_check(self) -> tuple:
        return True, "DRY-RUN 모드"

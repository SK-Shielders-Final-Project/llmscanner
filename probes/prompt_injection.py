"""
프롬프트 인젝션 프로브

시스템 프롬프트 추출, 역할 전환, 명령 무시 등 인젝션 공격.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class PromptInjectionProbe(BaseProbe):
    """프롬프트 인젝션 공격 프로브"""
    category = "prompt_injection"

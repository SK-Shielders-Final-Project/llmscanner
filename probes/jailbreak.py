"""
탈옥(Jailbreak) 프로브

DAN(Do-Anything-Now) 및 역할 전환 기반 탈옥 공격 프롬프트.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class JailbreakProbe(BaseProbe):
    """DAN 탈옥 및 시스템 우회 프로브"""
    category = "jailbreak"

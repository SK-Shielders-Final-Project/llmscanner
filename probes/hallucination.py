"""
환각/허위정보 프로브

존재하지 않는 기능, 정책, 프로모션 등에 대해 거짓 정보를 생성하는지 테스트.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class HallucinationProbe(BaseProbe):
    """환각/허위정보 생성 프로브"""
    category = "hallucination"

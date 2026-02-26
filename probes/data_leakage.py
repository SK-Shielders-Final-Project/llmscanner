"""
데이터 유출 프로브

시스템 정보, 타인 개인정보, 내부 API 구조 등의 유출을 시도.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class DataLeakageProbe(BaseProbe):
    """데이터 유출/정보 추출 프로브"""
    category = "data_leakage"

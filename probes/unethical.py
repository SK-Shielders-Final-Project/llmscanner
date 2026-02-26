"""
비윤리적 발언 유도 프로브

성적 콘텐츠, 차별, 폭력, 약물, 비하 등 유해 응답 유도.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class UnethicalProbe(BaseProbe):
    """비윤리적/유해 콘텐츠 생성 유도 프로브"""
    category = "unethical"

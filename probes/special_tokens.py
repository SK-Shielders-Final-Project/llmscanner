"""
특수 토큰 공격 프로브

Gemma 3의 특수 토큰(<start_of_turn>, <end_of_turn>, <bos>, <eos> 등)을
삽입하여 대화 흐름을 조작하고 안전 필터를 우회하는 공격.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class SpecialTokensProbe(BaseProbe):
    """특수 토큰 기반 대화 흐름 조작 프로브"""
    category = "special_tokens"

"""
코드 생성 취약점 프로브

LLM이 악의적인 Python/쉘 코드를 생성하는지 테스트.
프롬프트는 data.json에서 로딩.
"""

from probes import BaseProbe


class CodeGenerationProbe(BaseProbe):
    """악성 코드 생성 유도 프로브"""
    category = "code_generation"

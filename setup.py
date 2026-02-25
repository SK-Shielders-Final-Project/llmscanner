from setuptools import setup, find_packages

setup(
    name="vrompt",
    version="1.0.0",
    description="Vrompt — LLM 취약점 스캐너 (Garak 기반 경량 스캔 도구)",
    author="ZDME",
    py_modules=[
        "main",
        "scanner",
        "api_client",
        "detector",
        "report",
    ],
    packages=["probes"],
    include_package_data=True,
    install_requires=[
        "requests>=2.28.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "vrompt=main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)

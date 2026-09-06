"""Setup script for unified-vuln-db.

Original Plamen work. Licensed under MIT — see LICENSE in this directory
(same terms as the root Plamen LICENSE).
"""

from setuptools import setup, find_packages

setup(
    name="unified-vuln-db",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.0.0",
        "chromadb>=0.4.0",
        "sentence-transformers>=2.2.0",
        "httpx>=0.24.0",
        "aiofiles>=23.0.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "tenacity>=8.2.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "huggingface": ["datasets>=2.14.0"],
    },
    entry_points={
        "console_scripts": [
            "unified-vuln=unified_vuln.indexer:cli",
            "unified-vuln-server=unified_vuln.server:run",
        ],
    },
)

#!/usr/bin/env python3
"""
SecurityAgents Platform Setup

Installs and configures the SecurityAgents platform for production use.
"""

from setuptools import setup, find_packages

setup(
    name="security-agents-platform",
    version="2.0.0",
    description="Enterprise AI-Powered Security Operations Platform",
    author="SecurityAgents Tiger Teams",
    author_email="team@security-agents.ai",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "asyncio>=3.4.3",
        "aiohttp>=3.8.5", 
        "aiofiles>=23.2.1",
        "boto3>=1.28.0",
        "botocore>=1.31.0",
        "requests>=2.31.0",
        "httpx>=0.24.1",
        "pydantic>=2.4.0",
        "pydantic-settings>=2.0.3",
        "pyyaml>=6.0.1",
        "jsonschema>=4.19.0",
        "cryptography>=41.0.0",
        "python-jose[cryptography]>=3.3.0",
        "python-dotenv>=1.0.0",
        "environs>=9.5.0",
        "structlog>=23.1.0",
        "python-dateutil>=2.8.2",
        "typing-extensions>=4.7.1"
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "security-agents=security_agents.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
)
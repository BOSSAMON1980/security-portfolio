from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="web-security-scanner",
    version="2.0.0",
    author="Sean Amon",
    author_email="seanamon56@gmail.com",
    description="Advanced Web Application Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seanamon/web-security-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "argparse>=1.4.0",
    ],
    entry_points={
        "console_scripts": [
            "security-scanner=scanner:main",
        ],
    },
)

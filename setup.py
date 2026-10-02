#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/classifier/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-classifier",
    version=version_info["__version__"],
    description="File type classifier for Karton framework",
    namespace_packages=["karton"],
    packages=["karton.classifier"],
    license_files = ("LICENSE",),
    url="https://github.com/CERT-Polska/karton-classifier/",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.10",
    entry_points={
        'console_scripts': [
            'karton-classifier=karton.classifier:Classifier.main'
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)

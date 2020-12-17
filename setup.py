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
    install_requires=open("requirements.txt").read().splitlines(),
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

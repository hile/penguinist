"""
Scripts and system tool wrappers for linux

This module is split from penguinist module to platform dependent tool
"""

import glob

from setuptools import setup, find_packages

VERSION='4.1.0'

setup(
    name = 'penguinist',
    keywords = 'System Management Utility Linux Scripts',
    description = 'Sysadmin utility modules and scripts for linux',
    author = 'Ilkka Tuohela',
    author_email = 'hile@iki.fi',
    version = VERSION,
    url = 'https://github.com/hile/penguinist',
    license = 'PSF',
    scripts = glob.glob('bin/*'),
    packages = find_packages(),
    install_requires = (
        'systematic>=4.2.6',
        'seine>=3.0.2',
    ),
)


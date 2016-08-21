#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='gcoin',
      version='1.1.44',
      description='Python gcoin Tools',
      author='gcoin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/OpenNetworking/pygcointools',
      packages=['gcoin'],
      scripts=['pybtctool'],
      include_package_data=True,
      data_files=[("", ["LICENSE"])],
      )

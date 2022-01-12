#!/usr/bin/env python3
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read().replace('.. :changelog:', '')

requirements = [
    'web.py==0.62',
    'rwlock==0.0.7',
    'promise==2.3',
    'requests>=2.25.1',
]

test_requirements = [
    # TODO: put package test requirements here

]

setup(
    name='multiav',
    version='0.1.0',
    description="MultiAV scanner with Python and JSON API",
    long_description=readme + '\n\n' + history,
    author="Sakkiii",
    author_email='admin@sakkiii.com',
    url='https://github.com/multiav2/multiav',
    packages=[
        'multiav',
    ],
    package_dir={'multiav':
                 'multiav'},
    include_package_data=True,
    install_requires=requirements,
    license="ISCL",
    zip_safe=False,
    keywords='multiav',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    test_suite='tests',
    tests_require=test_requirements,
    scripts=[
        # 'multiav/scripts/multiav-client.py',
        'multiav/scripts/runserver.py']
)

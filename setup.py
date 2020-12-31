#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages
import os

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

with open('requirements.txt') as reqs_file:
    requirements = [i.strip() for i in reqs_file.readlines()]

with open('VERSION') as v_file:
    version = v_file.read().strip()

test_requirements = [
    'tox',
]

setup(
    name='ansible-vault-rekey',
    version=version,
    description="Roll keys and re-encrypt secrets in any repo using Ansible Vault",
    long_description=readme + '\n\n' + history,
    author="Shaun Martin",
    author_email='shaun@samsite.ca',
    url='https://github.com/inhumantsar/python-ansible-vault-rekey',
    packages=find_packages(include=['ansible_vault_rekey']),
    entry_points={
        'console_scripts': [
            'ansible-vault-rekey=ansible_vault_rekey.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="BSD license",
    zip_safe=False,
    keywords='ansible-vault-rekey',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    test_suite='tests',
    tests_require=test_requirements,
)

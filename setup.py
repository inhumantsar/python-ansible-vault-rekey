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

setup_requirements = [
    'pytest-runner',
]

with open('requirements_dev.txt') as devreqs_file:
    test_requirements = [i.strip() for i in devreqs_file.readlines()]

setup(
    name='ansible-vault-rekey',
    version='0.1.0',
    description="Roll keys and re-encrypt secrets in any repo using Ansible Vault",
    long_description=readme + '\n\n' + history,
    author="Shaun Martin",
    author_email='shaun@samsite.ca',
    url='https://github.com/inhumantsar/ansible_vault_rekey',
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
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    setup_requires=setup_requirements,
)

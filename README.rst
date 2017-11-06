===================
ansible-vault-rekey
===================


.. image:: https://img.shields.io/pypi/v/ansible_vault_rekey.svg
        :target: https://pypi.python.org/pypi/ansible_vault_rekey

.. image:: https://img.shields.io/travis/inhumantsar/ansible_vault_rekey.svg
        :target: https://travis-ci.org/inhumantsar/ansible_vault_rekey

.. image:: https://readthedocs.org/projects/ansible-vault-rekey/badge/?version=latest
        :target: https://ansible-vault-rekey.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/inhumantsar/ansible_vault_rekey/shield.svg
     :target: https://pyup.io/repos/github/inhumantsar/ansible_vault_rekey/
     :alt: Updates


Roll keys and re-encrypt secrets in any repo using Ansible Vault


* Free software: BSD license
* Documentation: https://ansible-vault-rekey.readthedocs.io.

Usage
-----

WARNING: Very few guardrails present. Running this without options *will* overwrite data by default.

Known issues / caveats:

* Shows a callous disregard for whitespace and comments
* Assumes it's in a playbook directory if `-r` isn't provided
* Will casually write secrets to STDOUT in `--debug` mode

.. code-block::

    $ ansible-vault-rekey --help
    Usage: ansible-vault-rekey [OPTIONS]

      (Re)keys Ansible Vault repos.

    Options:
      --debug
      --dry-run                 Skip any action that would overwrite an original
                                file.
      -k, --keep-backups        Keep unencrypted copies of files after a
                                successful rekey.
      -r, --code-path TEXT      Path to Ansible code.
      -p, --password-file TEXT  Path to password file. Default: vault-password.txt
      -v, --vars-file TEXT      Only operate on the file specified. Default is to
                                check every YAML file in Ansible role/play dirs
                                for encrypted assets.
      --help                    Show this message and exit.



Installation
------------

We have dependencies a couple of layers down which need to compile crypto libraries
if you haven't already got them. On most systems, you'll need the following:

* libffi-dev / libffi-devel
* libssl-dev / openssl-devel
* gcc

Features
--------

* TODO

Testing
-------

With Docker (recommended):

.. code-block::

    docker build -t tmp . && docker run --rm -it -w /workspace -v $(pwd):/workspace tmp

Manually:

.. code-block::

    pip install -r requirements.txt -r requirements_dev.txt && python2.7 -m pytest tests/*.py

Credits
---------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage

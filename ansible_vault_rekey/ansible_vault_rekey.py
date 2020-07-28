# -*- coding: utf-8 -*-

import errno
import fnmatch
import logging
import os
import random
import shutil
import string

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib
from ansible.parsing.vault import VaultSecret
from ansible.parsing.yaml.loader import AnsibleLoader

"""Main module."""

log = logging.getLogger()
# log.setLevel(logging.WARNING)
# log_console = logging.StreamHandler()
# log_console.setLevel(logging.DEBUG)
# log.addHandler(log_console)


def generate_password(length=128):
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))


def write_password_file(path, password=None, overwrite=False):
    password = generate_password() if not password else password
    if os.path.isfile(path) and not overwrite:
        log.error('Cowardly refusing to overwrite an existing password file at {}'.format(path))
        return False
    with open(path, 'w+') as f:
        f.write(password)
    return True


def restore_files(files, target_path, prefix='.'):
    restored = []
    for f in files:
        relpath = os.path.realpath(f)[len(os.path.realpath(prefix)) + 1:]
        newpath = os.path.join(target_path, relpath)
        try:
            os.makedirs(os.path.dirname(newpath))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        shutil.copy(f, newpath)
        restored.append(newpath)
    return restored


def backup_files(files, backup_path, prefix='.'):
    for f in files:
        relpath = os.path.realpath(f)[len(os.path.realpath(prefix)) + 1:]
        newpath = os.path.join(backup_path, relpath)
        try:
            os.makedirs(os.path.dirname(newpath))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        shutil.copy(f, newpath)
    return find_files(backup_path)


def find_files(path, pattern='*.*'):
    exclude = ['.rekey-backups', '.git', '.j2']
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude]  # this tells python to modify dirs in place
        for name in files:                               # without creating a new list
            if fnmatch.fnmatch(name, pattern):
                yield os.path.realpath(os.path.join(root, name))


def is_file_secret(path):
    with open(path, 'rb') as f:
        return True if f.readline().startswith(b'$ANSIBLE_VAULT;1.1;AES256') else False


def decrypt_file(path, password_file, newpath=None):
    '''Decrypts an Ansible Vault encrypted file and returns unmodified contents. Set newpath to
        write the result somewhere.'''
    log.debug('decrypt_file({}, {}, {})'.format(path, password_file, newpath))
    if is_file_secret(path):
        # log.debug('file is fully encrypted')
        with open(password_file, 'rb') as f:
            vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(f.read().strip()))])
        # log.debug('vault fetched with password file: {}'.format(password_file))
        with open(path, 'rb') as f:
            decrypted = vault.decrypt(f.read())
        # log.debug('loaded file: {}'.format(decrypted))

    if not decrypted:
        raise ValueError('The Vault library extracted nothing from the file. Is it actually encrypted?')

    if newpath:
        if not os.path.isdir(os.path.dirname(newpath)):
            os.makedirs(os.path.dirname(newpath))
        with open(newpath, 'wb') as f:
            f.write(decrypted)
    return decrypted


def encrypt_file(path, password_file, newpath=None, secrets=None):
    '''Encrypts an Ansible Vault file. Returns encrypted data. Set newpath to
        write the result somewhere. Set secrets to specify inline secret addresses.'''
    # log.debug('Reading decrypted data from {}...'.format(path))
    with open(path, 'rb') as f:
        data = f.read()

    if not data:
        raise ValueError('Unable to parse/read file {}'.format(path))
    else:
        log.debug('Got vars/file: {}'.format(data))

    with open(password_file) as f:
        p = f.read().strip()
        log.debug('Read pass from {}: {}'.format(password_file, p))

    vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(p.encode('utf-8')))])
    encrypted = vault.encrypt(data)
    with open(newpath, 'wb') as f:
        f.write(encrypted)
    return encrypted


def parse_yaml(path, secrets=None):
    with open(path) as f:
        data = AnsibleLoader(f.read(), vault_secrets=secrets).get_single_data()
        log.debug("Debug: {}".format(data))
        return data

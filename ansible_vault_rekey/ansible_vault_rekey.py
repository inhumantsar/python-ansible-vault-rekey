# -*- coding: utf-8 -*-

from collections import OrderedDict
from copy import deepcopy
import errno
import fnmatch
import logging
import os
import random
import shutil
import string
import yaml
import subprocess

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from ansible_vault_rekey.vaultstring import VaultString

"""Main module."""
yaml.add_representer(VaultString, VaultString.to_yaml, Dumper=yaml.Dumper)
yaml.add_constructor(VaultString.yaml_tag, VaultString.yaml_constructor)
log = logging.getLogger()
# log.setLevel(logging.WARNING)
# log_console = logging.StreamHandler()
# log_console.setLevel(logging.DEBUG)
# log.addHandler(log_console)


def get_dict_value(data, address):
    """Accepts a dictionary and an "address" (a list representing a nested dict value's key)
    and returns the value at that "address"
        >>> d = {'mailserver_users': [{'somekey': 'someval'}, ...], ...}
        >>> a = ['mailserver_users', 0, 'somekey']
        >>> get_dict_value(d, a)
        'someval'
    """
    d = deepcopy(data)
    for key in address:
        try:
            d = d[key]
        except KeyError:
            return None
    return d


def put_dict_value(data, address, value):
    """Accepts a dictionary and an "address" (a list representing a nested dict value's key)
    and sets the value at that "address".
        >>> d = {'mailserver_users': [{...}, {...}], ...}
        >>> a = ['mailserver_users', 1, 'newkey']
        >>> put_dict_value(d, a, 'newval')
        {..., 'mailserver_users': [{...}, {'newkey': 'newval', ...}]}
    """
    # i had like 15 lines here before finding this: https://stackoverflow.com/a/13688108/596204
    for key in address[:-1]:
        data = data[key]        # dive another layer deep
    data[address[-1]] = value   # set nested obj's value
    return data                  # return modified outer obj


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


def rekey_file(path, password_file, new_password_file):
    cmd = "ansible-vault rekey --vault-password-file {} --new-vault-password-file {} {}".format(
        password_file, new_password_file, path)
    subprocess.check_call(cmd, shell=True)
    return True


def decrypt_file(path, password_file, newpath=None):
    """Decrypts an Ansible Vault encrypted file and returns unmodified contents. Set newpath to
        write the result somewhere."""
    log.debug('decrypt_file({}, {}, {})'.format(path, password_file, newpath))
    decrypted = None
    if is_file_secret(path):
        # log.debug('file is fully encrypted')
        with open(password_file, 'rb') as f:
            vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(f.read().strip()))])
        # log.debug('vault fetched with password file: {}'.format(password_file))
        with open(path, 'rb') as f:
            decrypted = vault.decrypt(f.read())
        # log.debug('loaded file: {}'.format(decrypted))
    else:
        decrypted = parse_yaml(path)
        for secret in find_yaml_secrets(decrypted):
            v = get_dict_value(decrypted, secret)
            plaintext = v.decrypt(open(password_file).read().strip()).decode('utf-8')
            put_dict_value(decrypted, secret, plaintext)

    if not decrypted:
        raise ValueError('The Vault library extracted nothing from the file. Is it actually encrypted?')

    if newpath:
        if not os.path.isdir(os.path.dirname(newpath)):
            os.makedirs(os.path.dirname(newpath))
        with open(newpath, 'wb') as f:
            if not isinstance(decrypted, bytes):
                # yaml
                f.write(yaml.dump(decrypted).encode('utf-8'))
            else:
                f.write(decrypted)
    return decrypted


def encrypt_file(path, password_file, newpath=None, secrets=None):
    """Encrypts an Ansible Vault file. Returns encrypted data. Set newpath to
        write the result somewhere. Set secrets to specify inline secret addresses."""
    # log.debug('Reading decrypted data from {}...'.format(path))
    with open(path, 'r') as f:
        data = f.read()

    if not data:
        raise ValueError('Unable to parse/read file {}'.format(path))
    else:
        log.debug('Got vars/file: {}'.format(data))

    with open(password_file) as f:
        p = f.read().strip()
        log.debug('Read pass from {}: {}'.format(password_file, p))

    if secrets:
        data = parse_yaml(path)
        # newdata = data.copy()
        secrets = list(secrets)
        log.debug('Received {} secrets: {}'.format(len(secrets), secrets))
        for address in secrets:
            plaintext = get_dict_value(data, address)
            log.debug('Re-encrypting "{}" at {} with new password...'.format(plaintext, address))
            put_dict_value(data, address,
                           VaultString.encrypt(plaintext=plaintext, password=p))
        if newpath:
            log.debug('Writing {} to {}...'.format(data, newpath, p))
            write_yaml(newpath, data)
        return data
    else:
        vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(p.encode('utf-8')))])
        encrypted = vault.encrypt(data)
        with open(newpath, 'wb') as f:
            f.write(encrypted)
        return encrypted


def parse_yaml(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


def write_yaml(path, data):
    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    with open(path, 'w+') as f:
        f.write(yaml.dump(data, default_flow_style=False))


def find_yaml_secrets(data, path=None):
    """Generator which results a list of YAML key paths formatted as lists.
            >>> for i in find_yaml_secrets(data):
            ...   print(i)
            ...
            ['test_password']                       # data['test_password']
            ['mailserver_users', 0, 'password']     # data['mailserver_users'][0]['password']
    """
    path = [] if not path else path
    if data.__class__ is VaultString:
        yield path
    if isinstance(data, list):
        counter = 0
        for item in data:
            newpath = path + [counter]
            result = find_yaml_secrets(item, newpath)
            if result:
                for r in result:
                    yield r
            counter += 1
    # log.debug(data)
    if isinstance(data, dict) or isinstance(data, OrderedDict):
        for k, v in data.items():
            newpath = path + [k]
            result = find_yaml_secrets(v, newpath)
            if result:
                for r in result:
                    yield r

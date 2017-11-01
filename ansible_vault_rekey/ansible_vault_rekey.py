# -*- coding: utf-8 -*-

import errno
import fnmatch
import logging
import os
import random
import shutil
import string
import subprocess
import yaml

from ansible_vault import Vault

"""Main module."""

log = logging.getLogger()
log.setLevel(logging.DEBUG)
log_console = logging.StreamHandler()
log_console.setLevel(logging.DEBUG)
log.addHandler(log_console)


def get_dict_value(data, address):
    '''Accepts a dictionary and an "address" (a list representing a nested dict value's key)
    and returns the value at that "address"
        >>> d = {'mailserver_users': [{'somekey': 'someval'}, ...], ...}
        >>> a = ['mailserver_users', 0, 'somekey']
        >>> get_dict_value(d, a)
        'someval'
    '''
    d = data.copy()
    for key in address:
        try:
            d = d[key]
        except KeyError:
            return None
    return d

def put_dict_value(data, address, value):
    '''Accepts a dictionary and an "address" (a list representing a nested dict value's key)
    and sets the value at that "address".
        >>> d = {'mailserver_users': [{...}, {...}], ...}
        >>> a = ['mailserver_users', 1, 'newkey']
        >>> put_dict_value(d, a, 'newval')
        {..., 'mailserver_users': [{...}, {'newkey': 'newval', ...}]}
    '''
    # i had like 15 lines here before finding this: https://stackoverflow.com/a/13688108/596204
    r = data                    # stash a reference to the outermost obj
    for key in address[:-1]:
        data = data[key]        # dive another layer deep
    data[address[-1]] = value   # set nested obj's value
    return r                    # return modified outer obj


def generate_password(length=128):
    return ''.join(random.choice(string.printable) for _ in xrange(length))


def write_password_file(path, password=None, overwrite=False):
    password = generate_password() if not password else password
    if os.path.isfile(path) and not overwrite:
        log.error('Cowardly refusing to overwrite an existing password file at {}'.format(path))
        return False
    with open(path, 'w+') as f:
        f.write(password)
    return True


def restore_files(files, target_path):
    restored = []
    for f in files:
        relpath = os.path.realpath(f)[len(os.path.realpath('.'))+1:]
        newpath = os.path.join(target_path, relpath)
        try:
            os.makedirs(os.path.dirname(newpath))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        shutil.copy(f, newpath)
        restored.append(newpath)
    return restored


def backup_files(files, backup_path):
    for f in files:
        relpath = os.path.realpath(f)[len(os.path.realpath('.'))+1:]
        newpath = os.path.join(backup_path, relpath)
        try:
            os.makedirs(os.path.dirname(newpath))
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        shutil.copy(f, newpath)
    return find_files(backup_path)


def find_files(path, pattern='*.y*ml'):
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                yield os.path.join(root, name)

def is_file_secret(path):
    with open(path) as f:
        return True if f.readline().startswith('$ANSIBLE_VAULT;1.1;AES256') else False

def rekey_file(path, password_file, new_password_file):
    cmd = "ansible-vault rekey --vault-password-file {} --new-vault-password-file {} {}".format(
        password_file, new_password_file, path)
    subprocess.check_call(cmd, shell=True)
    return True

def decrypt_file(path, password_file, newpath=None):
    '''Decrypts an Ansible Vault YAML file and returns a dict. Set newpath to
        write the result somewhere.'''
    if is_file_secret(path):
        with open(password_file) as f:
            vault = Vault(f.read().strip())
        with open(path) as f:
            r = vault.load(f.read())
    else:
        r = parse_yaml(path)
        for s in find_yaml_secrets(r):
            v = get_dict_value(r, s)
            v.set_password_file(password_file)
            put_dict_value(r, s, v.plaintext)


    if not r:
        raise ValueError('The Vault library extracted nothing from the file. Is it actually encrypted?')

    if newpath:
        if not os.path.isdir(os.path.dirname(newpath)):
            os.makedirs(os.path.dirname(newpath))
        with open(newpath, 'w+') as f:
            f.write(yaml.dump(r))

    return r

def parse_yaml(path):
    try:
        with open(path) as f:
            return yaml.load(f.read())
    except Exception as e:
        log.error('Unable to parse YAML in {}. Exception: {}'.format(path, e))
        return None

def find_yaml_secrets(data, path=None):
    '''Generator which results a list of YAML key paths formatted as lists.
            >>> for i in find_yaml_secrets(data):
            ...   print(i)
            ...
            ['test_password']                       # data['test_password']
            ['mailserver_users', 0, 'password']     # data['mailserver_users'][0]['password']
    '''
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
    if isinstance(data, dict):
        for k, v in data.iteritems():
            newpath = path + [k]
            result = find_yaml_secrets(v, newpath)
            if result:
                for r in result:
                    yield r

def contains_yaml_secrets(data):
    return True if len(list(find_yaml_secrets(data))) > 0 else False


# Ansible Vault uses custom YAML tags to ID encrypted strings
# adapted from https://stackoverflow.com/a/43060743/596204
class VaultString(yaml.YAMLObject):
    yaml_tag = u'!vault'

    def __init__(self, ciphertext=None, plaintext=None, password_file='vault-password.txt'):
        self.vault = None
        self.plaintext = None
        self.ciphertext = None

        if password_file:
            self.set_password_file(password_file)

        if ciphertext:
            self.ciphertext = ciphertext.strip()
        elif plaintext and self.vault:
            self.ciphertext = self.vault.dump(plaintext)

        if plaintext:
            self.plaintext = plaintext.strip()
        elif ciphertext and self.vault:
            self.plaintext = self.vault.load(ciphertext)

    def set_password(self, password):
        self.vault = Vault(password)
        if self.plaintext and not self.ciphertext:
            self.ciphertext = self.vault.dump(self.plaintext)
        elif (not self.plaintext) and self.ciphertext:
            self.plaintext = self.vault.load(self.ciphertext)

    def set_password_file(self, password_file):
        if os.path.isfile(password_file):
            self.set_password(open(password_file,'r').read().strip())

    def __repr__(self):
        return 'VaultString({:.25}...)'.format(self.ciphertext)

    @classmethod
    def from_yaml(cls, loader, node):
        return VaultString(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.ciphertext)

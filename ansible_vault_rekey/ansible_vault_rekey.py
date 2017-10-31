# -*- coding: utf-8 -*-

import fnmatch
import logging
import os
import yaml

from ansible_vault import Vault

"""Main module."""

log = logging.getLogger()

def find_files(path, pattern='*.y*ml'):
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                yield os.path.join(root, name)

def parse_yaml(path):
    try:
        with open(path) as f:
            return yaml.load(f.read())
    except Exception as e:
        log.error('Unable to parse YAML in {}. Exception: {}'.format(path, e))
        return None

def find_secrets(data, path=None):
    '''Generator which results a list of YAML key paths formatted as lists.
            >>> for i in find_secrets(data):
            ...   print(i)
            ...
            ['test_password']                       # data['test_password']
            ['mailserver_users', 0, 'password']     # data['mailserver_users'][0]['password']
    '''
    path = [] if not path else path
    if isinstance(data, yaml.YAMLObject):
        yield path
    if isinstance(data, list):
        counter = 0
        for item in data:
            newpath = path + [counter]
            result = find_secrets(item, newpath)
            if result:
                for r in result:
                    yield r
            counter += 1
    if isinstance(data, dict):
        for k, v in data.iteritems():
            newpath = path + [k]
            result = find_secrets(v, newpath)
            if result:
                for r in result:
                    yield r

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

def contains_secrets(data):
    return True if len(list(find_secrets(data))) > 0 else False


# Ansible Vault uses custom YAML tags to ID encrypted strings
# adapted from https://stackoverflow.com/a/43060743/596204
class VaultString(yaml.YAMLObject):
    yaml_tag = u'!vault'

    def __init__(self, ciphertext):
        self.ciphertext = ciphertext

    def __repr__(self):
        return 'VaultString({:.25}...)'.format(self.ciphertext)

    def plaintext(self, password_file='vault-password.txt'):
        vault = Vault(open(password_file,'r').read().strip())
        return vault.load(self.ciphertext)

    @classmethod
    def from_yaml(cls, loader, node):
        return VaultString(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.ciphertext)

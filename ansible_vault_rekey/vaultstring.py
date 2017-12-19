import os
import yaml
from ansible_vault import Vault

import logging

log = logging.getLogger()

# Ansible Vault uses custom YAML tags to ID encrypted strings
# adapted from https://stackoverflow.com/a/43060743/596204
class VaultString:
    yaml_tag = u'!vault'

    def __repr__(self):
        return "VaultString({:.25})".format(self.ciphertext)

    def __init__(self, ciphertext):
        self.plaintext = None
        if isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode('utf-8')
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.strip()
        self.ciphertext = ciphertext

    @staticmethod
    def encrypt(plaintext, password):
        vs = VaultString(None)
        vs.plaintext = str(plaintext).strip()
        vs.vault = vs.get_vault(password)
        vs.ciphertext = vs.vault.dump(vs.plaintext).decode('utf-8')
        log.debug('VaultString.encrypt - encrypted {}'.format(vs.plaintext))
        log.debug('Decrypted ciphertext: {}'.format(vs.vault.load(vs.ciphertext)))
        return vs

    def decrypt(self, password):
        v = self.get_vault(password)
        self.plaintext = v.load(self.ciphertext)
        log.debug('VaultString.decrypt - read in: {}'.format(self.plaintext))
        return self.plaintext

    @staticmethod
    def get_vault(password):
        return Vault(password)

    # for ruamel.yaml
    @staticmethod
    def yaml_constructor(loader, node):
        return VaultString(loader.construct_scalar(node))

    @staticmethod
    def to_yaml(dumper, data):
        log.debug('VaultString.to_yaml: dumping {}'.format(data.ciphertext))
        return dumper.represent_scalar(data.yaml_tag, data.ciphertext, style='|')

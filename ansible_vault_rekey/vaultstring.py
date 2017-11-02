import os
import yaml
from ansible_vault import Vault


# Ansible Vault uses custom YAML tags to ID encrypted strings
# adapted from https://stackoverflow.com/a/43060743/596204
class VaultString(yaml.YAMLObject):
    yaml_tag = u'!vault'

    def __init__(self, ciphertext):
        self.vault = None
        self.plaintext = None

        self.ciphertext = ciphertext.strip() if isinstance(ciphertext,str) else ciphertext

        if self.vault:
            self.plaintext = self.vault.load(ciphertext)

    @staticmethod
    def encrypt(plaintext, password):
        vs = VaultString(None)
        vs.plaintext = plaintext.strip()
        vs.vault = vs.get_vault(password)
        vs.ciphertext = vs.vault.dump(plaintext)
        return vs

    def decrypt(self, password):
        if not self.vault:
            self.vault = VaultString.get_vault(password)
        self.plaintext = self.vault.load(self.ciphertext)
        return self.plaintext

    @staticmethod
    def get_vault(password):
        return Vault(password)

    def __repr__(self):
        return 'VaultString({:.25}...)'.format(self.ciphertext)

    @classmethod
    def from_yaml(cls, loader, node):
        return VaultString(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.ciphertext)

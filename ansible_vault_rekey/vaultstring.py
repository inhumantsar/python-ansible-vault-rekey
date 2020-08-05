from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib
from ansible.parsing.vault import VaultSecret


# Ansible Vault uses custom YAML tags to ID encrypted strings
# adapted from https://stackoverflow.com/a/43060743/596204
class VaultString:
    yaml_tag = u'!vault'

    def __repr__(self):
        return 'VaultString({:.25}...)'.format(self.ciphertext)

    def __init__(self, ciphertext):
        self.plaintext = None
        self.ciphertext = ciphertext.strip() if isinstance(ciphertext, str) else ciphertext

    @staticmethod
    def encrypt(plaintext, password):
        vs = VaultString(None)
        vs.plaintext = str(plaintext).strip()
        vs.vault = vs.get_vault(password)
        vs.ciphertext = vs.vault.encrypt(plaintext)
        return vs

    def decrypt(self, password):
        v = self.get_vault(password)
        self.plaintext = v.decrypt(self.ciphertext)
        return self.plaintext

    @staticmethod
    def get_vault(password):
        return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode('utf-8')))])

    # for ruamel.yaml
    @staticmethod
    def yaml_constructor(loader, node):
        return VaultString(loader.construct_scalar(node))

    @staticmethod
    def to_yaml(dumper, data):
        return dumper.represent_scalar(data.yaml_tag, data.ciphertext, style='|')

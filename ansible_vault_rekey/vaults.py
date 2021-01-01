import yaml

from pathlib import Path
from collections import OrderedDict
from copy import deepcopy

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from ansible_vault_rekey.vaultstring import VaultString

yaml.add_representer(VaultString, VaultString.to_yaml, Dumper=yaml.Dumper)
yaml.add_constructor(VaultString.yaml_tag, VaultString.yaml_constructor)

class VaultFile:

    @staticmethod
    def generator(path):
        with open(path, 'r') as f:
            if f.readline().startswith('$ANSIBLE_VAULT;1.1;AES256'):
                return VaultFile(path)
            else:
                return PartialVaultFile(path)

    def __init__(self, path):
        self.path = Path(path)

    def __str__(self):
        rel_path = self.path.relative_to(Path.cwd())
        return f"<{self.__class__.__name__} {rel_path}>"

    def is_decrypted(self):
        return (self.content != None)

    def decrypt(password):
        vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password))])
        self.content = vault.decrypt(f.read())

    def encrypt(password):
        vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password.encode('utf-8')))])
        encrypted = vault.encrypt(self.content)

        with self.path.open('rb') as f:
            f.write(encrypted)


class PartialVaultFile(VaultFile):
    class VaultString:
        yaml_tag = u'!vault'

        def __init__(self, ciphertext):
            self.ciphertext = ciphertext.strip() if isinstance(ciphertext, str) else ciphertext

        @staticmethod
        def yaml_constructor(loader, node):
            return VaultString(loader.construct_scalar(node))

        @staticmethod
        def to_yaml(dumper, data):
            return dumper.represent_scalar(data.yaml_tag, data.ciphertext, style='|')

    def __init__(self, path):
        super().__init__(path)

        # Parse YAML file
        with self.path.open('r') as f:
            self.yaml = yaml.load(f, Loader=yaml.Loader)

        # Store all secrets defined in YAML file
        self.secrets = self.find_secrets(self.yaml)

    def decrypt(password):
        self.content = deepcopy(self.yaml)
        for secret in self.secrets:
            entry = self.content

            for key in secret:
                entry = entry[key]

            vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password))])
            plaintext = vault.decrypt(entry).decode('utf-8')

            entry = self.content
            for key in secret:
                entry = entry[key]
            entry[secret[-1]] = plaintext


    def find_secrets(self, data, path=None):
        """Generator which results a list of YAML key paths formatted as lists.
                >>> for i in find_secrets(data):
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
                result = self.find_secrets(item, newpath)
                if result:
                    for r in result:
                        yield r
                counter += 1
        # log.debug(data)
        if isinstance(data, dict) or isinstance(data, OrderedDict):
            for k, v in data.items():
                newpath = path + [k]
                result = self.find_secrets(v, newpath)
                if result:
                    for r in result:
                        yield r

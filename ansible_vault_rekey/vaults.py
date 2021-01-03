import yaml
import logging

from pathlib import Path
from copy import deepcopy
from collections import OrderedDict

from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib, VaultSecret

from ansible_vault_rekey.vaultstring import VaultString
from ansible_vault_rekey.exceptions import EncryptError, DecryptError, BackupError

log = logging.getLogger()

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

    def __init__(self, rel_path):
        self.rel_path = rel_path
        self.path = rel_path.resolve()
        self.secrets = []
        self.content = None

    def __str__(self):
        return str(self.rel_path)

    def __resp__(self):
        return f"<{self.__class__.__name__} {self.rel_path}>"

    def has_secrets(self):
        return bool(self.secrets)

    def is_decrypted(self):
        return self.content is not None

    def decrypt(self, password):
        try:
            vault = self._get_vault(password)

            with self.path.open('rb') as f:
                self.content = vault.decrypt(f.read())
        except Exception as e:
            raise DecryptError(e.message)

    def encrypt(self, password):
        try:
            vault = self._get_vault(password)
            encrypted = vault.encrypt(self.content)

            with self.path.open('wb') as f:
                f.write(encrypted)

        except Exception as e:
            raise EncryptError(e.message)

    def backup(self, backup_dir):
        try:
            backup_path = backup_dir / self.rel_path

            # Create all required directories if not already exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            with backup_path.open('wb') as f:
                f.write(self.content)
        except Exception as e:
            raise BackupError(e.message)

    def _get_vault(self, password):
        if isinstance(password, str):
            password = password.encode('utf-8')

        return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(password))])


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
        self.secrets = list(self.find_secrets(self.yaml))

    def decrypt(self, password):
        self.content = deepcopy(self.yaml)
        vault = self._get_vault(password)

        for secret in self.secrets:
            entry = self.content

            for key in secret:
                entry = entry[key]

            plaintext = vault.decrypt(entry.ciphertext).decode('utf-8').strip()

            entry = self.content
            for key in secret[:-1]:
                entry = entry[key]
            entry[secret[-1]] = plaintext

    def encrypt(self, password):
        encrypted = deepcopy(self.content)
        vault = self._get_vault(password)

        for secret in self.secrets:
            entry = self.content

            for key in secret:
                entry = entry[key]

            ciphertext = vault.encrypt(entry).decode('utf-8').strip()

            entry = encrypted
            for key in secret[:-1]:
                entry = entry[key]
            entry[secret[-1]] = VaultString(ciphertext)

        with self.path.open('w') as f:
            f.write(yaml.dump(encrypted, default_flow_style=False))

    def backup(self, backup_dir):
        backup_path = backup_dir / self.rel_path

        # Create all required directories if not already exists
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        with backup_path.open('w') as f:
            f.write(yaml.dump(self.content, default_flow_style=False))

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

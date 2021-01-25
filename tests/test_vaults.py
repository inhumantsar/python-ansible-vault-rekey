#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `ansible_vault_rekey` package."""

from tests.test_setup import Tests
from ansible_vault_rekey.vaults import VaultFile, PartialVaultFile
from ansible_vault_rekey.exceptions import BackupError, EncryptError, DecryptError

class TestVault(Tests):

    def test_vault_secrets(self):
        no_secrets_vault = VaultFile.generator(self.tmpdir / 'local.yml')

        assert type(no_secrets_vault) is PartialVaultFile
        assert not no_secrets_vault.has_secrets()

        vault_file = VaultFile.generator(self.group_vars / 'encrypted.yml')

        assert type(vault_file) is VaultFile
        assert not vault_file.has_secrets()

    def test_bad_yml(self):
        bad_yml = VaultFile.generator(self.group_vars / 'bad.yml')

        assert bad_yml is None

    def test_vault_parameters(self):
        vault_file = VaultFile(self.group_vars / 'encrypted.yml')

        assert not vault_file.has_secrets()
        assert vault_file.content is None
        assert not vault_file.is_decrypted()

        no_secrets_vault = VaultFile.generator(self.tmpdir / 'local.yml')

        assert not vault_file.has_secrets()
        assert vault_file.content is None
        assert not vault_file.is_decrypted()

        partial_vault = PartialVaultFile(self.group_vars / 'inlinesecrets.yml')

        assert partial_vault.has_secrets()
        assert partial_vault.content is None
        assert not partial_vault.is_decrypted()

    def test_decryption(self):
        vault_file = VaultFile(self.group_vars / 'encrypted.yml')
        partial_vault = PartialVaultFile(self.group_vars / 'inlinesecrets.yml')

        vault_file.decrypt(self.password)
        assert vault_file.is_decrypted()
        assert vault_file.content is not None
        assert vault_file.content != self._get_content(vault_file.path)

        partial_vault.decrypt(self.password)
        assert partial_vault.is_decrypted()
        assert isinstance(partial_vault.content, dict)
        assert partial_vault.content != self._get_content(partial_vault.path)

    def test_encryption(self):
        new_pw = 'foobar123'

        vault_file = VaultFile(self.group_vars / 'encrypted.yml')
        vault_file_content = self._get_content(vault_file.path)
        partial_vault = PartialVaultFile(self.group_vars / 'inlinesecrets.yml')
        partial_vault_content = self._get_content(partial_vault.path)

        vault_file.decrypt(self.password)
        vault_file.encrypt(new_pw)

        # Assert that file contains different content due to encryption
        assert vault_file_content != self._get_content(vault_file.path)

        partial_vault.decrypt(self.password)
        partial_vault.encrypt(new_pw)

        # Assert that file contains different content due to encryption
        assert partial_vault_content != self._get_content(partial_vault.path)

    def test_encryption_decryption(self):
        new_pw = 'foobar123'

        for v_file in ['encrypted.yml', 'inlinesecrets.yml']:
            # Decrypt / encrypt vault files with new PW
            vault_file = VaultFile.generator(self.group_vars / v_file)
            vault_file.decrypt(self.password)
            vault_file.encrypt(new_pw)

            # Decrypt vault files with new PW
            vault_file = VaultFile.generator(self.group_vars / v_file)
            vault_file.decrypt(new_pw)

            # Assert that we can decrypt newly encrypted content
            assert vault_file.content is not None

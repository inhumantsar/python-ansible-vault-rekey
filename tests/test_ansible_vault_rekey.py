#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `ansible_vault_rekey` package."""

import os
import pytest
import time
from os.path import realpath, join

from click.testing import CliRunner

from ansible_vault_rekey import ansible_vault_rekey as rekey
from ansible_vault_rekey.vaultstring import VaultString
from ansible_vault_rekey import cli

PLAY=realpath('tests/testplay')
TMP_DIR='/tmp/python-ansible-vault-rekey-{}'.format(str(time.time()))

def test_find_files_yml():
    expected = [
        "local.yml",
        "group_vars/inlinesecrets.yml",
        "group_vars/bad.yml",
        "group_vars/nosecrets.yml"
    ]
    r = list(rekey.find_files(PLAY))
    for i in expected:
        assert realpath(join(PLAY, i)) in r

def test_find_files_all():
    expected = [
        "alt-vault-password.txt",
        "vault-password.txt",
        "local.yml",
        "group_vars/inlinesecrets.yml",
        "group_vars/bad.yml",
        "group_vars/nosecrets.yml"
    ]
    r = list(rekey.find_files(PLAY, '*'))
    for i in expected:
        assert realpath(join(PLAY, i)) in r

def test_parse_yaml_secrets():
    assert isinstance(rekey.parse_yaml(join(PLAY,"group_vars/inlinesecrets.yml")), dict)

def test_parse_yaml_nosecrets():
    assert isinstance(rekey.parse_yaml(join(PLAY, "group_vars/nosecrets.yml")), dict)

def test_parse_yaml_bad():
    with pytest.raises(Exception) as e:
        rekey.parse_yaml(join(PLAY, "group_vars/bad.yml"))

def test_find_yaml_secrets():
    d = rekey.parse_yaml(join(PLAY, "group_vars/inlinesecrets.yml"))
    expected = [
        ['password'],
        ['users', 0, 'password'],
        ['users', 1, 'secrets', 1]
    ]
    r = list(rekey.find_yaml_secrets(d))
    for i in expected:
        assert i in r

def test_find_yaml_secrets_none():
    d = rekey.parse_yaml(join(PLAY, "group_vars/nosecrets.yml"))
    expected = []
    r = list(rekey.find_yaml_secrets(d))
    assert expected == r

def test_get_dict_value():
    d = rekey.parse_yaml(join(PLAY, "group_vars/inlinesecrets.yml"))
    # expected = [
    #     ['password'],
    #     ['users', 0, 'password'],
    #     ['users', 1, 'secrets', 1]
    # ]
    r = rekey.find_yaml_secrets(d)
    for address in r:
        assert isinstance(rekey.get_dict_value(d, address), VaultString)

def test_get_dict_value_bad():
    d = rekey.parse_yaml(join(PLAY, "group_vars/inlinesecrets.yml"))
    assert rekey.get_dict_value(d, ['fake','address']) == None

def test_put_dict_value():
    d = rekey.parse_yaml(join(PLAY, "group_vars/nosecrets.yml"))
    oldval = [
        'one',
        'two',
        'three'
    ]
    address = ['moo', 'too']
    v = rekey.get_dict_value(d, address)
    assert isinstance(v, list)
    assert v == oldval
    assert rekey.put_dict_value(d, address, v + ['four']) != None

    newv = rekey.get_dict_value(d, address)
    assert isinstance(newv, list)
    assert newv == oldval + ['four']


def test_vaultstring_encrypt_decrypt():
    plaintext = 'moo too three'
    password_file = join(PLAY, 'vault-password.txt')
    expected = '''$ANSIBLE_VAULT;1.1;AES256'''
    v = rekey.VaultString.encrypt(plaintext=plaintext, password=open(password_file).read().strip())
    assert v.ciphertext.startswith(expected)

    decrypted = v.decrypt(password=open(password_file).read().strip())
    assert decrypted == plaintext


def test_rekey_file_withdecrypt():
    expected = rekey.parse_yaml(join(PLAY, "group_vars/nosecrets.yml"))
    path = join(PLAY,"group_vars/encrypted.yml")
    password_file = join(PLAY, "vault-password.txt")
    alt_password_file = join(PLAY, 'alt-vault-password.txt')
    rekey.rekey_file(path, password_file, alt_password_file)
    assert expected == rekey.decrypt_file(path, alt_password_file)

    rekey.rekey_file(path, alt_password_file, password_file)
    assert expected == rekey.decrypt_file(path, password_file)

def test_decrypt_file_tolocation():
    expected = rekey.parse_yaml(join(PLAY, "group_vars/nosecrets.yml"))
    path = join(PLAY,"group_vars/encrypted.yml")
    newpath = join(TMP_DIR, 'decrypted.yml')
    password_file = join(PLAY, "vault-password.txt")
    rekey.decrypt_file(path, password_file, newpath)
    assert expected == rekey.parse_yaml(newpath)

def test_decrypt_file_inlinesecrets():
    expected = rekey.parse_yaml(join(PLAY, "group_vars/inlinesecrets_decrypted.yml"))
    path = join(PLAY, "group_vars/inlinesecrets.yml")
    newpath = join(TMP_DIR, 'inlinesecrets_decrypted.yml')
    password_file = join(PLAY, "vault-password.txt")
    rekey.decrypt_file(path, password_file, newpath)
    assert expected == rekey.parse_yaml(newpath)

def test_backup_files():
    files = rekey.find_files(join(PLAY, "group_vars"), '*')
    backedup_files_relpaths = [realpath(i)[len(realpath('.'))+1:] for i in rekey.backup_files(files, join(TMP_DIR, 'test_backup'))]
    for i in files:
        assert realpath(i)[len(realpath('.'))+1:] in backedup_files_relpaths

def test_restore_files():
    files = rekey.find_files(join(PLAY, "group_vars"), '*')
    r = rekey.restore_files(files, target_path=join(TMP_DIR, 'test_restore'))
    found_files = [realpath(i)[len(realpath('.'))+1:] for i in rekey.find_files(join(TMP_DIR, 'test_restore'), pattern='*')]
    for i in files:
        assert realpath(i)[len(realpath('.'))+1:] in found_files

def test_generate_password():
    assert len(rekey.generate_password()) == 128

def test_write_password_file():
    assert rekey.write_password_file(join(TMP_DIR, 'test_write_password_file'))

def test_write_password_file_failnooverwrite():
    tmpfile = join(TMP_DIR, 'test_write_password_file_failnooverwrite')
    if not os.path.isfile(tmpfile):
        rekey.write_password_file(tmpfile)
    assert rekey.write_password_file(tmpfile) == False

def test_write_password_file_withoverwrite():
    tmpfile = join(TMP_DIR, 'test_write_password_file_withoverwrite')
    if not os.path.isfile(tmpfile):
        rekey.write_password_file(tmpfile)
    assert rekey.write_password_file(tmpfile, overwrite=True)


def test_write_password_file_custompass():
    rekey.write_password_file(join(TMP_DIR, 'test_write_password_file_custompass'),
        password='mootoothree', overwrite=True)
    with open(join(TMP_DIR, 'test_write_password_file_custompass')) as f:
        assert f.read().strip() == 'mootoothree'


def test_command_line_interface_help():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert 'Show this message and exit.' in help_result.output

def test_command_line_interface_dryrun():
    runner = CliRunner()
    dry_run_result = runner.invoke(cli.main, ['--debug', '--dry-run', '-r', PLAY])
    assert dry_run_result.exit_code == 0

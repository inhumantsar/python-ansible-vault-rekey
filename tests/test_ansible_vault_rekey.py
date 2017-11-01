#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `ansible_vault_rekey` package."""

import os
import pytest
import time
import yaml

from click.testing import CliRunner

from ansible_vault_rekey import ansible_vault_rekey as rekey
# from ansible_vault_rekey import cli

PLAY='tests/testplay'
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
        assert "{}/{}".format(PLAY, i) in r

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
        assert "{}/{}".format(PLAY, i) in r

def test_parse_yaml_secrets():
    assert isinstance(rekey.parse_yaml("{}/group_vars/inlinesecrets.yml".format(PLAY)), dict)

def test_parse_yaml_nosecrets():
    assert isinstance(rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY)), dict)

def test_parse_yaml_bad():
    assert rekey.parse_yaml("{}/group_vars/bad.yml".format(PLAY)) == None

def test_find_yaml_secrets():
    d = rekey.parse_yaml("{}/group_vars/inlinesecrets.yml".format(PLAY))
    expected = [
        ['password'],
        ['users', 0, 'password'],
        ['users', 1, 'secrets', 1]
    ]
    r = rekey.find_yaml_secrets(d)
    for i in expected:
        assert i in r

def test_find_yaml_secrets_none():
    d = rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY))
    expected = []
    r = list(rekey.find_yaml_secrets(d))
    assert expected == r

def test_get_dict_value():
    d = rekey.parse_yaml("{}/group_vars/inlinesecrets.yml".format(PLAY))
    # expected = [
    #     ['password'],
    #     ['users', 0, 'password'],
    #     ['users', 1, 'secrets', 1]
    # ]
    r = rekey.find_yaml_secrets(d)
    for address in r:
        assert isinstance(rekey.get_dict_value(d, address), yaml.YAMLObject)

def test_get_dict_value_bad():
    d = rekey.parse_yaml("{}/group_vars/inlinesecrets.yml".format(PLAY))
    assert rekey.get_dict_value(d, ['fake','address']) == None

def test_put_dict_value():
    d = rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY))
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

def test_contains_yaml_secrets():
    d = rekey.parse_yaml("{}/group_vars/inlinesecrets.yml".format(PLAY))
    assert rekey.contains_yaml_secrets(d) == True

def test_contains_yaml_secrets_nosecrets():
    d = rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY))
    assert rekey.contains_yaml_secrets(d) == False

def test_vaultstring_encrypt_decrypt():
    plaintext = 'moo too three'
    password_file = '{}/vault-password.txt'.format(PLAY)
    expected = '''$ANSIBLE_VAULT;1.1;AES256'''
    v = rekey.VaultString(plaintext=plaintext, password_file=password_file)
    assert v.ciphertext.startswith(expected)

    v = rekey.VaultString(ciphertext=v.ciphertext, password_file=password_file)
    assert v.plaintext == plaintext


def test_rekey_file_withdecrypt():
    expected = rekey.parse_yaml('{}/group_vars/nosecrets.yml'.format(PLAY))
    path = "{}/group_vars/encrypted.yml".format(PLAY)
    password_file = "{}/vault-password.txt".format(PLAY)
    alt_password_file = "{}/alt-vault-password.txt".format(PLAY)
    rekey.rekey_file(path, password_file, alt_password_file)
    assert expected == rekey.decrypt_file(path, alt_password_file)

    rekey.rekey_file(path, alt_password_file, password_file)
    assert expected == rekey.decrypt_file(path, password_file)

def test_decrypt_file_tolocation():
    expected = rekey.parse_yaml('{}/group_vars/nosecrets.yml'.format(PLAY))
    path = "{}/group_vars/encrypted.yml".format(PLAY)
    newpath = os.path.join(TMP_DIR, 'decrypted.yml')
    password_file = "{}/vault-password.txt".format(PLAY)
    rekey.decrypt_file(path, password_file, newpath)
    assert expected == rekey.parse_yaml(newpath)

def test_decrypt_file_inlinesecrets():
    expected = rekey.parse_yaml('{}/group_vars/inlinesecrets_decrypted.yml'.format(PLAY))
    path = "{}/group_vars/inlinesecrets.yml".format(PLAY)
    newpath = os.path.join(TMP_DIR, 'inlinesecrets_decrypted.yml')
    password_file = "{}/vault-password.txt".format(PLAY)
    rekey.decrypt_file(path, password_file, newpath)
    assert expected == rekey.parse_yaml(newpath)

def test_backup_files():
    files = rekey.find_files("{}/group_vars".format(PLAY), '*')
    backedup_files_relpaths = [os.path.realpath(i)[len(os.path.realpath('.'))+1:] for i in rekey.backup_files(files, os.path.join(TMP_DIR, 'test_backup'))]
    for i in files:
        assert os.path.realpath(i)[len(os.path.realpath('.'))+1:] in backedup_files_relpaths

def test_restore_files():
    files = rekey.find_files("{}/group_vars".format(PLAY), '*')
    r = rekey.restore_files(files, target_path=os.path.join(TMP_DIR, 'test_restore'))
    found_files = [os.path.realpath(i)[len(os.path.realpath('.'))+1:] for i in rekey.find_files(os.path.join(TMP_DIR, 'test_restore'), pattern='*')]
    for i in files:
        assert os.path.realpath(i)[len(os.path.realpath('.'))+1:] in found_files

def test_generate_password():
    assert len(rekey.generate_password()) == 128

def test_write_password_file():
    assert rekey.write_password_file(os.path.join(TMP_DIR, 'test_write_password_file'))

def test_write_password_file_failnooverwrite():
    tmpfile = os.path.join(TMP_DIR, 'test_write_password_file_failnooverwrite')
    if not os.path.isfile(tmpfile):
        rekey.write_password_file(tmpfile)
    assert rekey.write_password_file(tmpfile) == False

def test_write_password_file_withoverwrite():
    tmpfile = os.path.join(TMP_DIR, 'test_write_password_file_withoverwrite')
    if not os.path.isfile(tmpfile):
        rekey.write_password_file(tmpfile)
    assert rekey.write_password_file(tmpfile, overwrite=True)


def test_write_password_file_custompass():
    rekey.write_password_file(os.path.join(TMP_DIR, 'test_write_password_file_custompass'),
        password='mootoothree', overwrite=True)
    with open(os.path.join(TMP_DIR, 'test_write_password_file_custompass')) as f:
        assert f.read().strip() == 'mootoothree'


# def test_command_line_interface():
#     """Test the CLI."""
#     runner = CliRunner()
#     result = runner.invoke(cli.main)
#     assert result.exit_code == 0
#     assert 'ansible_vault_rekey.cli.main' in result.output
#     help_result = runner.invoke(cli.main, ['--help'])
#     assert help_result.exit_code == 0
#     assert '--help  Show this message and exit.' in help_result.output

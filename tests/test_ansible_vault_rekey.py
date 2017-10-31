#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `ansible_vault_rekey` package."""

import pytest
import yaml

from click.testing import CliRunner

from ansible_vault_rekey import ansible_vault_rekey as rekey
# from ansible_vault_rekey import cli

PLAY='tests/testplay'

def test_find_files_yml():
    expected = [
        "local.yml",
        "group_vars/secrets.yml",
        "group_vars/bad.yml",
        "group_vars/nosecrets.yml"
    ]
    r = list(rekey.find_files(PLAY))
    for i in expected:
        assert "{}/{}".format(PLAY, i) in r

def test_find_files_all():
    expected = [
        "encrypted_file.txt",
        "plaintext_file.txt",
        "vault-password.txt",
        "local.yml",
        "group_vars/secrets.yml",
        "group_vars/bad.yml",
        "group_vars/nosecrets.yml"
    ]
    r = list(rekey.find_files(PLAY, '*'))
    for i in expected:
        assert "{}/{}".format(PLAY, i) in r

def test_parse_yaml_secrets():
    assert isinstance(rekey.parse_yaml("{}/group_vars/secrets.yml".format(PLAY)), dict)

def test_parse_yaml_nosecrets():
    assert isinstance(rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY)), dict)

def test_parse_yaml_bad():
    assert rekey.parse_yaml("{}/group_vars/bad.yml".format(PLAY)) == None

def test_find_secrets():
    d = rekey.parse_yaml("{}/group_vars/secrets.yml".format(PLAY))
    expected = [
        ['password'],
        ['users', 0, 'password'],
        ['users', 1, 'secrets', 1]
    ]
    r = rekey.find_secrets(d)
    for i in expected:
        assert i in r

def test_find_secrets_none():
    d = rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY))
    expected = []
    r = list(rekey.find_secrets(d))
    assert expected == r

def test_get_dict_value():
    d = rekey.parse_yaml("{}/group_vars/secrets.yml".format(PLAY))
    # expected = [
    #     ['password'],
    #     ['users', 0, 'password'],
    #     ['users', 1, 'secrets', 1]
    # ]
    r = rekey.find_secrets(d)
    for address in r:
        assert isinstance(rekey.get_dict_value(d, address), yaml.YAMLObject)

def test_get_dict_value_bad():
    d = rekey.parse_yaml("{}/group_vars/secrets.yml".format(PLAY))
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

def test_contains_secrets():
    d = rekey.parse_yaml("{}/group_vars/secrets.yml".format(PLAY))
    assert rekey.contains_secrets(d) == True

def test_contains_secrets_nosecrets():
    d = rekey.parse_yaml("{}/group_vars/nosecrets.yml".format(PLAY))
    assert rekey.contains_secrets(d) == False

# def test_command_line_interface():
#     """Test the CLI."""
#     runner = CliRunner()
#     result = runner.invoke(cli.main)
#     assert result.exit_code == 0
#     assert 'ansible_vault_rekey.cli.main' in result.output
#     help_result = runner.invoke(cli.main, ['--help'])
#     assert help_result.exit_code == 0
#     assert '--help  Show this message and exit.' in help_result.output

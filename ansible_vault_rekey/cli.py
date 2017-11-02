# -*- coding: utf-8 -*-

"""(Re)keys Ansible Vault repos."""

import click
import fnmatch
import logging
import os
import shutil
import sys

import ansible_vault_rekey as rekey
from ansible_vault_rekey import VaultString


log = logging.getLogger()
log.setLevel(logging.DEBUG)


log_console = logging.StreamHandler()
log_console.setLevel(logging.INFO)
log.addHandler(log_console)

@click.command()
@click.option('--debug', 'debug', default=False, is_flag=True)
@click.option('--dry-run', 'dry_run', default=False, is_flag=True,
              help="Skip any action that would overwrite an original file.")
@click.option('--keep-backups', '-k', 'keep_backups', default=False,
    help='Keep unencrypted copies of files after a successful rekey.')
@click.option('--code-path', '-r', 'code_path', default='.',
    help='Path to Ansible code.')
@click.option('--password-file', '-p', 'password_file', default=None,
    type=str, help='Path to password file. Default: vault-password.txt')
@click.option('--vars-file', '-v', 'varsfile', type=str, default=None,
    help='Only operate on the file specified. Default is to check every YAML file in Ansible role/play dirs for encrypted assets.')
def main(password_file, varsfile, code_path, dry_run, keep_backups, debug):
    """(Re)keys Ansible Vault repos."""
    if debug:
        log_console.setLevel(logging.DEBUG)

    if not os.path.isdir(code_path):
        log.error("{} doesn't seem to exist".format(code_path))
        sys.exit(1)
    code_path = os.path.realpath(code_path)

    backup_path = os.path.join(code_path,".ansible-vault-rekey-backups")

    if not password_file:
        password_file = os.path.join(code_path, 'vault-password.txt')
    else:
        if not os.path.isfile(password_file):
            log.error("{} doesn't seem to exist".format(password_file))
            sys.exit(1)
        password_file = os.path.realpath(password_file)


    # find all YAML files
    files = [os.path.realpath(varsfile)] if varsfile else rekey.find_files(code_path)

    vault_files = []
    for f in files:
        if rekey.is_file_secret(f):
            vault_files.append({'file': f})
            continue

        data = rekey.parse_yaml(f)
        secrets = rekey.find_yaml_secrets(data) if data else None
        # can't len() a generator, so we peek at next(). if it throws StopIteration
        # then there are no secrets in the file
        try:
            next(secrets)
        except StopIteration:
            # list(secrets) == []
            continue
        except TypeError:
            # secrets == None
            continue

        vault_files.append({'file': f, 'secrets': secrets})

    log.debug('Found vault-enabled files: {}'.format(vault_files))


    log.info('Backing up encrypted and password files...')
    # backup password file
    rekey.backup_files([password_file], backup_path, code_path)

    # decrypt and write files out to unencbackup location (same relative paths)
    for f in vault_files:
        newpath = os.path.join(backup_path, f['file'][len(code_path)+1:])
        log.debug('Decrypting {} to {} using {}'.format(f['file'], newpath, password_file))
        rekey.decrypt_file(f['file'], password_file, newpath)


    # generate new password file
    log.info('Generating new password file...')
    if dry_run:
        log.info('>> Dry run enabled, skipping overwrite. <<')
    else:
        rekey.write_password_file(password_file, overwrite=True)


    # loop through encrypted asset list, re-encrypt and overwrite originals
    log.info('Re-encrypting assets with new password file...')
    for f in vault_files:
        oldpath = os.path.join(backup_path, f['file'])
        newpath = os.path.realpath(f['file'])
        # newpath = os.path.realpath(f['file'])[len(os.path.realpath('.'))+1:]
        log.debug('Encrypting {} to {}'.format(oldpath, newpath))
        if dry_run:
            log.info('>> Dry run enabled, skipping overwrite. <<')
            r = True
        else:
            r = rekey.encrypt_file(oldpath, password_file, newpath,
                   f['secrets'] if 'secrets' in f.keys() else None)
        if not r:
            log.error('Encryption failed on {}'.format(oldpath))


    # test decryption of newly written assets?

    # remove backups
    if not keep_backups:
        log.info('Removing backups...')
        shutil.rmtree(backup_path)


if __name__ == "__main__":
    main()

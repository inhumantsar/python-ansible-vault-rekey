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
@click.option('--keep-backups', '-k', 'keep_backups', default=False, is_flag=True,
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

    backup_path = os.path.join(code_path,".rekey-backups")
    log.debug('Backup path set to: {}'.format(backup_path))

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

        try:
            data = rekey.parse_yaml(f)
        except Exception as e:
            log.warning('Unable to parse file, probably not valid yaml: {}'.format(happy_relpath(f)))
            continue

        # enh, generator. w/e.
        secrets = list(rekey.find_yaml_secrets(data)) if data else None
        if secrets and len(secrets) > 0:
            vault_files.append({'file': f, 'secrets': secrets})

    vflog = []
    for i in vault_files:
        suffix = " (whole)" if 'secrets' not in i.keys() else ""
        vflog.append("{}{}".format(happy_relpath(i['file']), suffix))

    log.debug('Found {} vault-enabled files: {}'.format(len(vflog), ', '.join(vflog)))


    log.info('Backing up encrypted and password files...')
    # backup password file
    rekey.backup_files([password_file], backup_path, code_path)

    # decrypt and write files out to unencbackup location (same relative paths)
    for f in vault_files:
        newpath = os.path.join(backup_path, f['file'][len(code_path)+1:])
        log.debug('Decrypting {} to {} using {}'.format(
            happy_relpath(f['file']), happy_relpath(newpath), happy_relpath(password_file)))
        rekey.decrypt_file(f['file'], password_file, newpath)


    # generate new password file
    log.info('Generating new password file...')
    if dry_run:
        log.info('>> Dry run enabled, skipping overwrite. <<')
    else:
        rekey.write_password_file(password_file, overwrite=True)
        log.info('Password file written: {}'.format(happy_relpath(password_file)))


    # loop through encrypted asset list, re-encrypt and overwrite originals
    log.info('Re-encrypting assets with new password file...')
    for f in vault_files:
        # log.debug('Raw file obj: {}'.format(f))
        oldpath = os.path.join(backup_path, happy_relpath(f['file']))
        newpath = os.path.realpath(f['file'])
        log.debug('Encrypting {} to {}'.format(happy_relpath(oldpath), happy_relpath(newpath)))
        if dry_run:
            log.info('>> Dry run enabled, skipping overwrite. <<')
            r = True
        else:
            r = rekey.encrypt_file(oldpath, password_file, newpath, f.get('secrets', None))
        if not r:
            log.error('Encryption failed on {}'.format(oldpath))


    # test decryption of newly written assets?

    # remove backups
    if not keep_backups:
        log.info('Removing backups...')
        shutil.rmtree(backup_path)

    log.info('Done!')

def happy_relpath(path):
     return path.replace(os.getcwd(), '.')



if __name__ == "__main__":
    main()

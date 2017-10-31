# -*- coding: utf-8 -*-

"""(Re)keys Ansible Vault repos."""

import click
import os
import fnmatch
import ansible_vault_rekey as rekey
import logging


log = logging.getLogger()
log.setLevel(logging.DEBUG)

log_console = logging.StreamHandler()
log_console.setLevel(logging.INFO)
log.addHandler(log_console)

@click.command()
@click.command('--debug', 'debug', default=False)
@click.option('--repo-path', '-r', 'repo_path', default='.',
    help='Path to an Ansible repo. Default: "."')
@click.option('--keep-backups', '-k', 'keep_backups', default=False,
    help='Keep unencrypted copies of files after a successful rekey.')
@click.option('--generate-only', '-g', 'generate_only', default=False,
    help='Only generate a new password file (will not overwrite)')
@click.option('--password-file', '-p', 'pwdfile', default="vault-password.txt",
    type=str, help='Path to password file. Default: vault-password.txt')
@click.option('--vars-file', '-v', 'varsfile', type=str, default=None,
    help='Only operate on the file specified. Default is to check every YAML file in Ansible role/play dirs for encrypted assets.')
def main(pwdfile, varsfile, generate_only, keep_backups, repo_path, debug):
    """(Re)keys Ansible Vault repos."""
    if debug:
        log_console.setLevel(logging.DEBUG)

    # find all files
    files = [varsfile] if varsfile else rekey.find_files(repo_path, '*')
    count_raw = len(files)

    # note encrypted files
    encfiles = []
    for f in files:
        with open(f) as fh:
            header = f.readline()
        if header.startswith('$ANSIBLE_VAULT'):
            encfiles.append((f, None))

        # check each file for YAML; if YAML, check for for encrypted strings
        if f.endswith('yml') or f.endswith('yaml'):
            # returns a generator (list) of key "addresses" where secrets are
            s = rekey.find_secrets(f)
            if s:
                encfiles.append(f, s)
    print(encfiles)

    # copy encrypted files or files with secrets to encbackup location


    # copy old vault-password file to encbackupbackup location
    # decrypt and write files out to unencbackup location (same relative paths)
    # generate new password file
    # loop through encrypted asset list, re-encrypt and overwrite originals
    # test decryption of newly written assets
    # remove backups



if __name__ == "__main__":
    main()

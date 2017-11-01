# -*- coding: utf-8 -*-

"""(Re)keys Ansible Vault repos."""

import click
import os
import fnmatch
import ansible_vault_rekey as rekey
import logging


BACKUP_PATH = ".ansible-vault-rekey-backups"

log = logging.getLogger()
log.setLevel(logging.DEBUG)


# log_console = logging.StreamHandler()
# log_console.setLevel(logging.INFO)
# log.addHandler(log_console)
#
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

    # find all YAML files
    files = [varsfile] if varsfile else rekey.find_files(repo_path)
    count_raw = len(files)

    vault_files = []
    for f in files:
        if rekey.is_file_secret(f):
            vault_files.append({'file': f})
            continue

        data = rekey.parse_yaml()
        secrets = rekey.find_yaml_secrets(data) if data else None
        if secrets:
            vault_files.append({'file': f, 'secrets': secrets})
            continue
    log.debug('Found vault-enabled files: {}'.format(vault_files))


    log.info('Backing up encrypted files...')

    # backup password file
    rekey.backup_files(pwdfile, BACKUP_PATH)

    # decrypt and write files out to unencbackup location (same relative paths)
    for f in vault_files:
        newpath = os.path.join(BACKUP_PATH, os.path.basename(f['file']))
        rekey.decrypt_file(path, pwdfile, newpath)
        log.debug('Decrypted {} to {}')


    # generate new password file
    newpwdfile = os.path.join(os.path.dirname(pwdfile), "{}.new".format(pwdfile))
    rekey.write_password_file(newpwdfile)

    # loop through encrypted asset list, re-encrypt and overwrite originals
    # test decryption of newly written assets
    # remove backups



if __name__ == "__main__":
    main()

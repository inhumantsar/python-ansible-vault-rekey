# -*- coding: utf-8 -*-

"""(Re)keys Ansible Vault repos."""

import click
import logging
import os
import shutil
import secrets
import string
import sys

from pathlib import Path

from ansible_vault_rekey.vaults import VaultFile, PartialVaultFile
from ansible_vault_rekey.exceptions import BackupError, EncryptError, DecryptError

log = logging.getLogger()
log.setLevel(logging.DEBUG)

log_console = logging.StreamHandler()
log_console.setLevel(logging.INFO)
log.addHandler(log_console)


@click.command()
@click.option('--debug', 'debug', default=False, is_flag=True)
@click.option('--dry-run', 'dry_run', default=False, is_flag=True,
              help="Skip any action that would overwrite an original file.")
@click.option('--backup', '-k', type=str,
              help='Keep unencrypted copies of files after a successful rekey.')
@click.option('--code-path', '-r', 'code_path', default='.', type=click.Path(exists=True, file_okay=False,
                writable=True), help='Path to Ansible code.')
@click.option('--password-file', '-p', 'password_file', default='vault-password.txt', type=click.File('rb'),
                help='Path to password file; - means STDIN. Default: vault-password.txt')
@click.option('--generate-password', 'gen_pw', type=click.IntRange(min=8),
                help='Generate random password of size;')
@click.option('--vars-file', '-v', 'varsfile', type=str, default=None,
              help='Only operate on the file specified. Default is to check every file for encrypted assets.')
def main(password_file, varsfile, code_path, dry_run, backup, debug, gen_pw):
    code_path = Path(code_path)

    vaults = []
    exclude = ['.rekey-backups', '.git', '.j2']

    # find all files
    for f in code_path.rglob('*.y*ml'):

        # Filter out files which are in excluded directory
        if any(d in str(f) for d in exclude):
            continue

        vault = VaultFile.generator(f)

        # Only add vault instances which are complete or has secrets
        if type(vault) is VaultFile or vault.has_secrets():
            vaults.append(vault)
            log.debug("Found %s file", vault)

    # Read password from file
    password = password_file.read().strip()
    log.info("Found %d vaults files in %s", len(vaults), code_path)

    # Parse new password for Vault files
    if not gen_pw:
        new_password = click.prompt('Enter new vault password', hide_input=True, confirmation_prompt=True)
    else:
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(gen_pw))

    for vault in vaults:
        try:
            vault.decrypt(password)

            if not dry_run:
                vault.encrypt(new_password)

            # Backup if backup_path is given
            if backup_path:
                vault.backup(backup_path)

        except DecryptError as de:
            log.error('Could not decrypt %s: %s', vault, de, exc_info=debug)

        except EncryptError as ee:
            log.error('Could not encrypt %s: %s', vault, ee, exc_info=debug)

        except BackupError as be:
            log.error('Could not backup %s: %s', vault, be, exc_info=debug)

        except Exception as e:
            log.error('Unknown error occured for %s: %s', vault, e, exc_info=debug)

if __name__ == "__main__":
    main()

class BackupError(Exception):
    """ BackupError

    Exception type used for handling errors in backup process
    """
    pass

class EncryptError(Exception):
    """ EncryptError

    Exception type used for handling errors in encryption process
    """
    pass

class DecryptError(Exception):
    """ DecryptError

    Exception type used for handling errors in decryption process
    """
    pass

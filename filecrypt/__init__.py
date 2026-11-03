"""filecrypt - authenticated AES-256-GCM file encryption.

Example:
    >>> from filecrypt import encrypt_file, decrypt_file
    >>> encrypt_file("secret.txt", "secret.txt.fc", "correct horse battery staple")
    >>> decrypt_file("secret.txt.fc", "secret.txt", "correct horse battery staple")
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Goutam Singh"
__email__ = "25mcaa22@kristujayanti.com"
__license__ = "MIT"

from .crypto import (
    CHUNK_SIZE,
    DEFAULT_SUFFIX,
    MAGIC,
    VERSION,
    DecryptionResult,
    EncryptionResult,
    FileCryptError,
    FileHeader,
    decrypt_file,
    derive_key,
    encrypt_file,
    read_header,
)

__all__ = [
    "__version__",
    "CHUNK_SIZE",
    "DEFAULT_SUFFIX",
    "MAGIC",
    "VERSION",
    "DecryptionResult",
    "EncryptionResult",
    "FileCryptError",
    "FileHeader",
    "decrypt_file",
    "derive_key",
    "encrypt_file",
    "read_header",
]

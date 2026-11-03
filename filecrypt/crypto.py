"""Authenticated, streaming file encryption built on AES-256-GCM.

The on-disk format is deliberately small and self describing::

    magic (8) | version (1) | salt (16) | nonce (12)
    | name length (2) | name | ciphertext | tag (16)

The header is passed to GCM as associated data, so the stored file name and
format fields cannot be altered without the authentication check failing.
Ciphertext is streamed in chunks so files larger than memory can be handled.
"""

from __future__ import annotations

import os
import struct
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = [
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

PathLike = Union[str, os.PathLike]

MAGIC = b"FCRYPT01"
VERSION = 1
DEFAULT_SUFFIX = ".fc"

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024
MAX_NAME_LENGTH = 0xFFFF

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

_HEADER = struct.Struct(">8sB16s12sH")
_HEADER_SIZE = _HEADER.size


class FileCryptError(Exception):
    """Raised when a file cannot be encrypted, decrypted or inspected."""


@dataclass(frozen=True)
class FileHeader:
    """Metadata read from the beginning of a filecrypt archive."""

    version: int
    salt: bytes
    nonce: bytes
    original_name: str
    header_size: int
    file_size: int
    raw_header: bytes = field(repr=False)

    @property
    def ciphertext_size(self) -> int:
        """Number of encrypted bytes in the archive (excluding the tag)."""
        return self.file_size - self.header_size - TAG_SIZE


@dataclass(frozen=True)
class EncryptionResult:
    """Summary of a completed encryption."""

    input_path: Path
    output_path: Path
    original_name: str
    plaintext_size: int
    archive_size: int


@dataclass(frozen=True)
class DecryptionResult:
    """Summary of a completed decryption."""

    input_path: Path
    output_path: Path
    original_name: str
    plaintext_size: int


def derive_key(
    password: str | bytes,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """Derive a 256-bit key from ``password`` and ``salt`` using scrypt.

    Args:
        password: The user supplied password (encoded as UTF-8 when a string).
        salt: A random salt of exactly :data:`SALT_SIZE` bytes.
        n: scrypt CPU/memory cost parameter. Must be a power of two.
        r: scrypt block size.
        p: scrypt parallelisation parameter.

    Returns:
        A 32 byte key suitable for AES-256.

    Raises:
        FileCryptError: If the password is empty.
        ValueError: If the salt length is wrong.
    """
    password_bytes = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not password_bytes:
        raise FileCryptError("password must not be empty")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be exactly {SALT_SIZE} bytes")

    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(password_bytes)


def read_header(path: PathLike) -> FileHeader:
    """Read and validate the header of a filecrypt archive.

    Args:
        path: Archive to inspect.

    Returns:
        The parsed :class:`FileHeader`.

    Raises:
        FileCryptError: If the file is missing, truncated or not an archive.
    """
    archive = Path(path)
    _validate_source(archive)
    try:
        file_size = archive.stat().st_size
    except OSError as error:
        raise FileCryptError(f"could not inspect {archive}: {error}") from error

    try:
        with archive.open("rb") as handle:
            fixed = handle.read(_HEADER_SIZE)
            if len(fixed) < _HEADER_SIZE:
                raise FileCryptError(f"{archive} is not a filecrypt archive (file too small)")

            magic, version, salt, nonce, name_length = _HEADER.unpack(fixed)
            if magic != MAGIC:
                raise FileCryptError(f"{archive} is not a filecrypt archive (bad magic)")
            if version != VERSION:
                raise FileCryptError(f"unsupported archive version {version}")

            name_bytes = handle.read(name_length)
            if len(name_bytes) != name_length:
                raise FileCryptError(f"{archive} has a truncated header")
    except OSError as error:
        raise FileCryptError(f"could not read {archive}: {error}") from error

    try:
        original_name = name_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FileCryptError(f"{archive} contains an invalid file name") from error

    header_size = _HEADER_SIZE + name_length
    if file_size < header_size + TAG_SIZE:
        raise FileCryptError(f"{archive} is truncated")

    return FileHeader(
        version=version,
        salt=salt,
        nonce=nonce,
        original_name=original_name,
        header_size=header_size,
        file_size=file_size,
        raw_header=fixed + name_bytes,
    )


def encrypt_file(
    source: PathLike,
    destination: PathLike,
    password: str | bytes,
    *,
    force: bool = False,
    remove_source: bool = False,
) -> EncryptionResult:
    """Encrypt ``source`` into ``destination`` with AES-256-GCM.

    Args:
        source: File to encrypt.
        destination: Archive to create.
        password: Password used to derive the encryption key.
        force: Overwrite ``destination`` when it already exists.
        remove_source: Delete the plaintext file after a successful run.

    Returns:
        An :class:`EncryptionResult` describing the operation.

    Raises:
        FileCryptError: If validation, reading, writing or key derivation fails.
    """
    source_path = Path(source)
    destination_path = Path(destination)

    _validate_source(source_path)
    _validate_destination(source_path, destination_path, force=force)

    name_bytes = source_path.name.encode("utf-8")
    if len(name_bytes) > MAX_NAME_LENGTH:
        raise FileCryptError("the source file name is too long to store in the archive")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    header = _HEADER.pack(MAGIC, VERSION, salt, nonce, len(name_bytes)) + name_bytes

    temp_path: Path | None = None
    try:
        temp_path = _make_temp(destination_path)
        with source_path.open("rb") as source_handle, temp_path.open("wb") as output:
            output.write(header)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(header)

            plaintext_size = 0
            for chunk in _iter_chunks(source_handle):
                plaintext_size += len(chunk)
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)

        os.replace(temp_path, destination_path)
        temp_path = None
    except OSError as error:
        raise FileCryptError(f"could not encrypt {source_path}: {error}") from error
    finally:
        if temp_path is not None:
            _remove_quietly(temp_path)

    if remove_source:
        _remove_source(source_path, "encrypted")

    return EncryptionResult(
        input_path=source_path,
        output_path=destination_path,
        original_name=source_path.name,
        plaintext_size=plaintext_size,
        archive_size=len(header) + plaintext_size + TAG_SIZE,
    )


def decrypt_file(
    source: PathLike,
    destination: PathLike,
    password: str | bytes,
    *,
    force: bool = False,
    remove_source: bool = False,
) -> DecryptionResult:
    """Decrypt a filecrypt archive into ``destination``.

    The tag is verified before the temporary plaintext file is moved into
    place, so a wrong password or a corrupted archive never leaves partially
    decrypted output behind.

    Args:
        source: Archive to decrypt.
        destination: File to write the plaintext to.
        password: Password used to derive the encryption key.
        force: Overwrite ``destination`` when it already exists.
        remove_source: Delete the archive after a successful run.

    Returns:
        A :class:`DecryptionResult` describing the operation.

    Raises:
        FileCryptError: If the archive is invalid or authentication fails.
    """
    source_path = Path(source)
    destination_path = Path(destination)

    header = read_header(source_path)
    _validate_destination(source_path, destination_path, force=force)
    key = derive_key(password, header.salt)

    temp_path: Path | None = None
    try:
        temp_path = _make_temp(destination_path)
        with source_path.open("rb") as source_handle, temp_path.open("wb") as output:
            source_handle.seek(header.file_size - TAG_SIZE)
            tag = source_handle.read(TAG_SIZE)

            source_handle.seek(header.header_size)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(header.raw_header)

            remaining = header.ciphertext_size
            plaintext_size = 0
            try:
                while remaining > 0:
                    chunk = source_handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise FileCryptError(f"{source_path} is truncated")
                    remaining -= len(chunk)
                    plaintext_size += len(chunk)
                    output.write(decryptor.update(chunk))
                output.write(decryptor.finalize())
            except InvalidTag as error:
                raise FileCryptError(
                    "decryption failed: wrong password or corrupted archive"
                ) from error

        os.replace(temp_path, destination_path)
        temp_path = None
    except OSError as error:
        raise FileCryptError(f"could not decrypt {source_path}: {error}") from error
    finally:
        if temp_path is not None:
            _remove_quietly(temp_path)

    if remove_source:
        _remove_source(source_path, "decrypted")

    return DecryptionResult(
        input_path=source_path,
        output_path=destination_path,
        original_name=header.original_name,
        plaintext_size=plaintext_size,
    )


def _iter_chunks(handle: BinaryIO, size: int = CHUNK_SIZE) -> Iterator[bytes]:
    while True:
        chunk = handle.read(size)
        if not chunk:
            return
        yield chunk


def _validate_source(path: Path) -> None:
    if not path.exists():
        raise FileCryptError(f"{path} does not exist")
    if not path.is_file():
        raise FileCryptError(f"{path} is not a regular file")


def _validate_destination(source: Path, destination: Path, *, force: bool) -> None:
    if destination.exists():
        if destination.is_dir():
            raise FileCryptError(f"{destination} is a directory")
        if not force:
            raise FileCryptError(f"{destination} already exists (use --force to overwrite)")

    try:
        same_file = source.resolve() == destination.resolve()
    except OSError:
        same_file = False
    if same_file:
        raise FileCryptError("input and output must be different files")


def _make_temp(destination: Path) -> Path:
    parent = destination.parent
    if not parent.exists():
        raise FileCryptError(f"output directory {parent} does not exist")

    handle, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(parent))
    os.close(handle)
    return Path(name)


def _remove_quietly(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _remove_source(path: Path, action: str) -> None:
    try:
        path.unlink()
    except OSError as error:
        raise FileCryptError(
            f"{action} successfully but could not remove {path}: {error}"
        ) from error

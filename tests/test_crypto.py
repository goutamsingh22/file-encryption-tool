"""Tests for the encryption core."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from filecrypt import (
    CHUNK_SIZE,
    FileCryptError,
    decrypt_file,
    derive_key,
    encrypt_file,
    read_header,
)
from filecrypt.crypto import MAGIC, SALT_SIZE, TAG_SIZE

PASSWORD = "correct horse battery staple"


class CryptoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path


class TestRoundTrip(CryptoTestCase):
    def test_text_file_round_trip(self) -> None:
        source = self.write("hello.txt", b"hello world\n")
        archive = self.directory / "hello.txt.fc"
        target = self.directory / "restored.txt"

        result = encrypt_file(source, archive, PASSWORD)
        self.assertEqual(result.plaintext_size, 12)
        self.assertGreater(result.archive_size, 12)

        restored = decrypt_file(archive, target, PASSWORD)
        self.assertEqual(restored.plaintext_size, 12)
        self.assertEqual(target.read_bytes(), b"hello world\n")
        self.assertEqual(restored.original_name, "hello.txt")

    def test_empty_file_round_trip(self) -> None:
        source = self.write("empty.bin", b"")
        archive = self.directory / "empty.fc"
        target = self.directory / "empty.out"

        encrypt_file(source, archive, PASSWORD)
        decrypt_file(archive, target, PASSWORD)

        self.assertEqual(target.read_bytes(), b"")

    def test_binary_file_larger_than_one_chunk(self) -> None:
        data = os.urandom(CHUNK_SIZE * 2 + 12345)
        source = self.write("big.bin", data)
        archive = self.directory / "big.fc"
        target = self.directory / "big.out"

        encrypt_file(source, archive, PASSWORD)
        decrypt_file(archive, target, PASSWORD)

        self.assertEqual(target.read_bytes(), data)

    def test_unicode_file_name_round_trip(self) -> None:
        source = self.write("résumé-日本語.txt", b"data")
        archive = self.directory / "unicode.fc"
        target = self.directory / "unicode.out"

        encrypt_file(source, archive, PASSWORD)
        header = read_header(archive)
        decrypt_file(archive, target, PASSWORD)

        self.assertEqual(header.original_name, "résumé-日本語.txt")
        self.assertEqual(target.read_bytes(), b"data")

    def test_byte_password_is_accepted(self) -> None:
        source = self.write("bytes.txt", b"secret")
        archive = self.directory / "bytes.fc"
        target = self.directory / "bytes.out"

        encrypt_file(source, archive, PASSWORD.encode("utf-8"))
        decrypt_file(archive, target, PASSWORD.encode("utf-8"))

        self.assertEqual(target.read_bytes(), b"secret")


class TestAuthentication(CryptoTestCase):
    def test_wrong_password_is_rejected(self) -> None:
        source = self.write("secret.txt", b"top secret")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"

        encrypt_file(source, archive, PASSWORD)

        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, "wrong password")

        self.assertFalse(target.exists())

    def test_tampered_ciphertext_is_rejected(self) -> None:
        source = self.write("secret.txt", b"top secret")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"

        encrypt_file(source, archive, PASSWORD)
        data = bytearray(archive.read_bytes())
        data[-TAG_SIZE - 1] ^= 0x01
        archive.write_bytes(bytes(data))

        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, PASSWORD)

        self.assertFalse(target.exists())

    def test_tampered_header_is_rejected(self) -> None:
        source = self.write("a.txt", b"data")
        archive = self.directory / "a.fc"
        target = self.directory / "a.out"

        encrypt_file(source, archive, PASSWORD)
        data = bytearray(archive.read_bytes())
        name_offset = len(MAGIC) + 1 + SALT_SIZE + 12 + 2
        data[name_offset] = ord("b")
        archive.write_bytes(bytes(data))

        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, PASSWORD)

        self.assertFalse(target.exists())

    def test_existing_output_survives_failed_decryption(self) -> None:
        source = self.write("secret.txt", b"top secret")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"
        target.write_bytes(b"do not lose me")

        encrypt_file(source, archive, PASSWORD)

        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, "wrong password", force=True)

        self.assertEqual(target.read_bytes(), b"do not lose me")

    def test_truncated_archive_is_rejected(self) -> None:
        source = self.write("secret.txt", b"top secret")
        archive = self.directory / "secret.fc"

        encrypt_file(source, archive, PASSWORD)
        data = archive.read_bytes()
        archive.write_bytes(data[: len(data) - 20])

        with self.assertRaises(FileCryptError):
            read_header(archive)

    def test_truncated_ciphertext_is_rejected(self) -> None:
        source = self.write("secret.txt", b"top secret")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"

        encrypt_file(source, archive, PASSWORD)
        archive.write_bytes(archive.read_bytes()[:-1])

        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, PASSWORD)

        self.assertFalse(target.exists())

    def test_bad_magic_is_rejected(self) -> None:
        fake = self.write("fake.fc", b"not an archive at all, definitely not")
        with self.assertRaises(FileCryptError):
            read_header(fake)

    def test_empty_password_is_rejected(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.directory / "secret.fc"

        with self.assertRaises(FileCryptError):
            encrypt_file(source, archive, "")

        self.assertFalse(archive.exists())

    def test_no_temporary_files_are_left_behind(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"

        encrypt_file(source, archive, PASSWORD)
        with self.assertRaises(FileCryptError):
            decrypt_file(archive, target, "wrong password")

        leftovers = list(self.directory.glob("*.tmp"))
        self.assertEqual(leftovers, [])


class TestFileHandling(CryptoTestCase):
    def test_refuses_to_overwrite_without_force(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.write("secret.fc", b"existing")

        with self.assertRaises(FileCryptError):
            encrypt_file(source, archive, PASSWORD)

        self.assertEqual(archive.read_bytes(), b"existing")

    def test_force_overwrites(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.write("secret.fc", b"existing")

        encrypt_file(source, archive, PASSWORD, force=True)

        self.assertNotEqual(archive.read_bytes(), b"existing")
        self.assertEqual(read_header(archive).original_name, "secret.txt")

    def test_input_and_output_must_differ(self) -> None:
        source = self.write("secret.txt", b"data")

        with self.assertRaises(FileCryptError):
            encrypt_file(source, source, PASSWORD, force=True)

    def test_missing_input_is_rejected(self) -> None:
        with self.assertRaises(FileCryptError):
            encrypt_file(self.directory / "nope.txt", self.directory / "nope.fc", PASSWORD)

    def test_missing_output_directory_is_rejected(self) -> None:
        source = self.write("secret.txt", b"data")
        with self.assertRaises(FileCryptError):
            encrypt_file(source, self.directory / "missing" / "secret.fc", PASSWORD)

    def test_remove_source_after_encryption(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.directory / "secret.fc"

        encrypt_file(source, archive, PASSWORD, remove_source=True)

        self.assertFalse(source.exists())
        self.assertTrue(archive.exists())

    def test_remove_source_after_decryption(self) -> None:
        source = self.write("secret.txt", b"data")
        archive = self.directory / "secret.fc"
        target = self.directory / "secret.out"

        encrypt_file(source, archive, PASSWORD)
        decrypt_file(archive, target, PASSWORD, remove_source=True)

        self.assertFalse(archive.exists())
        self.assertEqual(target.read_bytes(), b"data")


class TestHeader(CryptoTestCase):
    def test_header_fields(self) -> None:
        source = self.write("report.pdf", b"pdf bytes")
        archive = self.directory / "report.fc"

        encrypt_file(source, archive, PASSWORD)
        header = read_header(archive)

        self.assertEqual(header.version, 1)
        self.assertEqual(header.original_name, "report.pdf")
        self.assertEqual(len(header.salt), SALT_SIZE)
        self.assertEqual(len(header.nonce), 12)
        self.assertEqual(header.file_size, archive.stat().st_size)
        self.assertEqual(header.header_size, 8 + 1 + 16 + 12 + 2 + len("report.pdf"))
        self.assertEqual(header.ciphertext_size, len(b"pdf bytes"))

    def test_each_archive_uses_a_fresh_salt_and_nonce(self) -> None:
        source = self.write("secret.txt", b"same data")
        first = self.directory / "first.fc"
        second = self.directory / "second.fc"

        encrypt_file(source, first, PASSWORD)
        encrypt_file(source, second, PASSWORD)

        first_header = read_header(first)
        second_header = read_header(second)
        self.assertNotEqual(first_header.salt, second_header.salt)
        self.assertNotEqual(first_header.nonce, second_header.nonce)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())


class TestDeriveKey(unittest.TestCase):
    def test_derivation_is_deterministic(self) -> None:
        salt = bytes(range(SALT_SIZE))
        self.assertEqual(derive_key("password", salt), derive_key("password", salt))

    def test_derivation_depends_on_salt(self) -> None:
        first = derive_key("password", bytes(range(SALT_SIZE)))
        second = derive_key("password", bytes(reversed(range(SALT_SIZE))))
        self.assertNotEqual(first, second)

    def test_derived_key_length(self) -> None:
        self.assertEqual(len(derive_key("password", os.urandom(SALT_SIZE))), 32)


if __name__ == "__main__":
    unittest.main()

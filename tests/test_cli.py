"""Tests for the command line interface."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from filecrypt.cli import _default_decrypt_name, _safe_name, main

PASSWORD = "correct horse battery staple"


def run(*argv: str) -> tuple[int, str, str]:
    """Run the CLI and capture stdout, stderr and the exit code."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path


class TestEncryptDecrypt(CliTestCase):
    def test_encrypt_then_decrypt(self) -> None:
        source = self.write("notes.txt", b"hello cli\n")
        archive = self.directory / "notes.txt.fc"
        target = self.directory / "notes.out"

        code, out, _ = run("encrypt", str(source), str(archive), "-p", PASSWORD)
        self.assertEqual(code, 0)
        self.assertIn("Encrypted", out)
        self.assertTrue(archive.exists())

        code, out, _ = run("decrypt", str(archive), str(target), "-p", PASSWORD)
        self.assertEqual(code, 0)
        self.assertIn("Decrypted", out)
        self.assertEqual(target.read_bytes(), b"hello cli\n")

    def test_default_output_names(self) -> None:
        source = self.write("notes.txt", b"hello")

        code, _, _ = run("encrypt", str(source), "-p", PASSWORD)
        self.assertEqual(code, 0)
        archive = self.directory / "notes.txt.fc"
        self.assertTrue(archive.exists())

        source.unlink()
        code, _, _ = run("decrypt", str(archive), "-p", PASSWORD)
        self.assertEqual(code, 0)
        self.assertEqual(source.read_bytes(), b"hello")

    def test_remove_source(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"

        code, _, _ = run("encrypt", str(source), str(archive), "-p", PASSWORD, "--remove-source")
        self.assertEqual(code, 0)
        self.assertFalse(source.exists())

        target = self.directory / "restored.txt"
        code, _, _ = run(
            "decrypt", str(archive), str(target), "-p", PASSWORD, "--remove-source"
        )
        self.assertEqual(code, 0)
        self.assertFalse(archive.exists())
        self.assertEqual(target.read_bytes(), b"hello")

    def test_output_directory(self) -> None:
        source = self.write("notes.txt", b"hello")
        output_dir = self.directory / "out"
        output_dir.mkdir()

        code, _, _ = run("encrypt", str(source), str(output_dir), "-p", PASSWORD)
        self.assertEqual(code, 0)
        self.assertTrue((output_dir / "notes.txt.fc").exists())

    def test_restore_name(self) -> None:
        source = self.write("original.txt", b"hello")
        archive = self.directory / "renamed.fc"
        run("encrypt", str(source), str(archive), "-p", PASSWORD)

        restored = self.directory / "elsewhere"
        restored.mkdir()
        moved = restored / "something.fc"
        archive.replace(moved)

        code, _, _ = run("decrypt", str(moved), "-p", PASSWORD, "--restore-name")
        self.assertEqual(code, 0)
        self.assertEqual((restored / "original.txt").read_bytes(), b"hello")

    def test_restore_name_does_not_escape_the_directory(self) -> None:
        source = self.write("safe.txt", b"hello")
        archive = self.directory / "safe.fc"
        run("encrypt", str(source), str(archive), "-p", PASSWORD)

        data = bytearray(archive.read_bytes())
        name_offset = 8 + 1 + 16 + 12 + 2
        data[name_offset : name_offset + len("safe.txt")] = b"../evil.t"
        archive.write_bytes(bytes(data))

        code, _, _ = run("decrypt", str(archive), "-p", PASSWORD, "--restore-name")
        self.assertEqual(code, 2)
        self.assertFalse((self.directory.parent / "evil.t").exists())


class TestPasswordSources(CliTestCase):
    def test_password_file(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"
        password_file = self.write("password.txt", PASSWORD.encode("utf-8") + b"\n")

        code, _, _ = run(
            "encrypt", str(source), str(archive), "--password-file", str(password_file)
        )
        self.assertEqual(code, 0)

        target = self.directory / "notes.out"
        code, _, _ = run(
            "decrypt", str(archive), str(target), "--password-file", str(password_file)
        )
        self.assertEqual(code, 0)
        self.assertEqual(target.read_bytes(), b"hello")

    def test_empty_password_file(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"
        password_file = self.write("empty.txt", b"")

        code, _, err = run(
            "encrypt", str(source), str(archive), "--password-file", str(password_file)
        )

        self.assertEqual(code, 2)
        self.assertIn("empty", err)

    def test_password_env(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"
        target = self.directory / "notes.out"

        with mock.patch.dict(os.environ, {"FILECRYPT_TEST_PASSWORD": PASSWORD}):
            code, _, _ = run(
                "encrypt", str(source), str(archive), "--password-env", "FILECRYPT_TEST_PASSWORD"
            )
            self.assertEqual(code, 0)
            code, _, _ = run(
                "decrypt", str(archive), str(target), "--password-env", "FILECRYPT_TEST_PASSWORD"
            )
            self.assertEqual(code, 0)

        self.assertEqual(target.read_bytes(), b"hello")

    def test_missing_environment_variable(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"

        with mock.patch.dict(os.environ, {}, clear=True):
            code, _, err = run(
                "encrypt", str(source), str(archive), "--password-env", "NOT_SET_ANYWHERE"
            )

        self.assertEqual(code, 2)
        self.assertIn("not set", err)

    def test_no_password_without_a_terminal(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"

        with mock.patch("filecrypt.cli.sys.stdin.isatty", return_value=False):
            code, _, err = run("encrypt", str(source), str(archive))

        self.assertEqual(code, 2)
        self.assertIn("no password supplied", err)

    def test_short_password_warns(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"

        code, _, err = run("encrypt", str(source), str(archive), "-p", "short")

        self.assertEqual(code, 0)
        self.assertIn("warning", err)


class TestErrors(CliTestCase):
    def test_wrong_password_returns_exit_code_2(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.directory / "notes.fc"
        target = self.directory / "notes.out"
        run("encrypt", str(source), str(archive), "-p", PASSWORD)

        code, _, err = run("decrypt", str(archive), str(target), "-p", "wrong password")

        self.assertEqual(code, 2)
        self.assertIn("wrong password", err)
        self.assertFalse(target.exists())

    def test_refuses_to_overwrite(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.write("notes.fc", b"existing")

        code, _, err = run("encrypt", str(source), str(archive), "-p", PASSWORD)

        self.assertEqual(code, 2)
        self.assertIn("already exists", err)

    def test_force_overwrites(self) -> None:
        source = self.write("notes.txt", b"hello")
        archive = self.write("notes.fc", b"existing")

        code, _, _ = run("encrypt", str(source), str(archive), "-p", PASSWORD, "--force")

        self.assertEqual(code, 0)
        self.assertNotEqual(archive.read_bytes(), b"existing")

    def test_missing_input(self) -> None:
        code, _, err = run(
            "encrypt", str(self.directory / "missing.txt"), "-p", PASSWORD
        )

        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)


class TestInfo(CliTestCase):
    def test_info_shows_metadata(self) -> None:
        source = self.write("report.pdf", b"pdf bytes")
        archive = self.directory / "report.fc"
        run("encrypt", str(source), str(archive), "-p", PASSWORD)

        code, out, _ = run("info", str(archive))

        self.assertEqual(code, 0)
        self.assertIn("filecrypt v1", out)
        self.assertIn("report.pdf", out)
        self.assertIn("Payload     : 9 bytes", out)

    def test_info_rejects_a_plain_file(self) -> None:
        plain = self.write("plain.txt", b"not encrypted")

        code, _, err = run("info", str(plain))

        self.assertEqual(code, 2)
        self.assertIn("not a filecrypt archive", err)


class TestNameHandling(unittest.TestCase):
    def test_safe_name_strips_paths(self) -> None:
        self.assertEqual(_safe_name("../../etc/passwd"), "passwd")
        self.assertEqual(_safe_name("..\\..\\windows\\system32\\config"), "config")
        self.assertEqual(_safe_name("plain.txt"), "plain.txt")

    def test_safe_name_rejects_empty_values(self) -> None:
        for name in ("", ".", "..", "   "):
            self.assertIsNone(_safe_name(name))

    def test_default_decrypt_name(self) -> None:
        self.assertEqual(_default_decrypt_name(Path("notes.txt.fc")), "notes.txt")
        self.assertEqual(_default_decrypt_name(Path("notes.bin")), "notes.bin.dec")


if __name__ == "__main__":
    unittest.main()

"""Command line interface for filecrypt."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .crypto import (
    DEFAULT_SUFFIX,
    FileCryptError,
    decrypt_file,
    encrypt_file,
    read_header,
)

__all__ = ["main", "build_parser"]

MIN_RECOMMENDED_PASSWORD = 8


def _add_password_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-p",
        "--password",
        help="password to use (visible in the process list; prefer a prompt or env var)",
    )
    group.add_argument(
        "--password-file",
        metavar="PATH",
        help="read the password from the first line of PATH",
    )
    group.add_argument(
        "--password-env",
        metavar="VAR",
        help="read the password from environment variable VAR",
    )


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str:
    if args.password is not None:
        password = args.password
    elif args.password_file is not None:
        try:
            lines = Path(args.password_file).read_text(encoding="utf-8-sig").splitlines()
        except OSError as error:
            raise FileCryptError(
                f"could not read a password from {args.password_file}: {error}"
            ) from error
        if not lines:
            raise FileCryptError(f"password file {args.password_file} is empty")
        password = lines[0]
    elif args.password_env is not None:
        password = os.environ.get(args.password_env)
        if password is None:
            raise FileCryptError(f"environment variable {args.password_env} is not set")
    elif sys.stdin.isatty():
        prompt = "New password: " if confirm else "Password: "
        password = getpass.getpass(prompt)
        if confirm:
            repeated = getpass.getpass("Confirm password: ")
            if password != repeated:
                raise FileCryptError("passwords do not match")
    else:
        raise FileCryptError(
            "no password supplied; use --password, --password-file, --password-env "
            "or run from an interactive terminal"
        )

    if not password:
        raise FileCryptError("password must not be empty")
    return password


def _warn_if_weak(password: str) -> None:
    if len(password) < MIN_RECOMMENDED_PASSWORD:
        print(
            f"warning: passwords shorter than {MIN_RECOMMENDED_PASSWORD} characters "
            "are easy to brute-force",
            file=sys.stderr,
        )


def _resolve_output(output: str | None, default_path: Path) -> Path:
    if output is None:
        return default_path
    candidate = Path(output)
    if candidate.is_dir():
        return candidate / default_path.name
    return candidate


def _safe_name(name: str) -> str | None:
    """Reduce a stored name to a safe basename, or return ``None``."""
    cleaned = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if cleaned in ("", ".", ".."):
        return None
    return cleaned


def _default_decrypt_name(source: Path) -> str:
    if source.name.endswith(DEFAULT_SUFFIX):
        return source.name[: -len(DEFAULT_SUFFIX)]
    return source.name + ".dec"


def cmd_encrypt(args: argparse.Namespace) -> int:
    source = Path(args.input)
    destination = _resolve_output(
        args.output, source.with_name(source.name + DEFAULT_SUFFIX)
    )
    password = _read_password(args, confirm=True)
    _warn_if_weak(password)

    result = encrypt_file(
        source,
        destination,
        password,
        force=args.force,
        remove_source=args.remove_source,
    )

    print(f"Encrypted {result.input_path} -> {result.output_path}")
    print(
        f"  {result.plaintext_size} bytes plaintext -> "
        f"{result.archive_size} bytes archive (AES-256-GCM)"
    )
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    source = Path(args.input)
    header = read_header(source)

    stored_name: str | None = None
    if args.restore_name:
        stored_name = _safe_name(header.original_name)
        if stored_name is None:
            raise FileCryptError(
                "the archive does not contain a usable file name; pass an output path"
            )

    name = stored_name or _default_decrypt_name(source)
    if args.output is None:
        destination = source.with_name(name)
    else:
        destination = Path(args.output)
        if destination.is_dir():
            destination = destination / name

    password = _read_password(args, confirm=False)

    result = decrypt_file(
        source,
        destination,
        password,
        force=args.force,
        remove_source=args.remove_source,
    )

    print(f"Decrypted {result.input_path} -> {result.output_path}")
    print(f"  {result.plaintext_size} bytes restored (AES-256-GCM)")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    header = read_header(args.input)

    print(f"File        : {args.input}")
    print(f"Format      : filecrypt v{header.version} (AES-256-GCM, scrypt)")
    print(f"Original    : {header.original_name}")
    print(f"Archive size: {header.file_size} bytes")
    print(f"Payload     : {header.ciphertext_size} bytes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``filecrypt`` command."""
    parser = argparse.ArgumentParser(
        prog="filecrypt",
        description="Encrypt and decrypt files with AES-256-GCM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  filecrypt encrypt report.pdf\n"
            "  filecrypt decrypt report.pdf.fc\n"
            "  filecrypt encrypt notes.txt notes.fc --password-env FILECRYPT_PASSWORD\n"
            "  filecrypt info notes.fc\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    encrypt = subparsers.add_parser(
        "encrypt", help="encrypt a file", description="Encrypt a file into a .fc archive."
    )
    encrypt.add_argument("input", help="file to encrypt")
    encrypt.add_argument(
        "output",
        nargs="?",
        help="archive to create (default: INPUT.fc)",
    )
    encrypt.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    encrypt.add_argument(
        "--remove-source",
        action="store_true",
        help="delete the plaintext file after successful encryption",
    )
    _add_password_options(encrypt)
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = subparsers.add_parser(
        "decrypt", help="decrypt a file", description="Decrypt a .fc archive."
    )
    decrypt.add_argument("input", help="archive to decrypt")
    decrypt.add_argument(
        "output",
        nargs="?",
        help="file to write (default: INPUT without .fc)",
    )
    decrypt.add_argument("-f", "--force", action="store_true", help="overwrite the output file")
    decrypt.add_argument(
        "--restore-name",
        action="store_true",
        help="use the file name stored in the archive instead of the input name",
    )
    decrypt.add_argument(
        "--remove-source",
        action="store_true",
        help="delete the archive after successful decryption",
    )
    _add_password_options(decrypt)
    decrypt.set_defaults(func=cmd_decrypt)

    info = subparsers.add_parser(
        "info", help="show archive metadata", description="Show metadata without decrypting."
    )
    info.add_argument("input", help="archive to inspect")
    info.set_defaults(func=cmd_info)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``filecrypt`` command.

    Args:
        argv: Command line arguments. Defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args) or 0)
    except FileCryptError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

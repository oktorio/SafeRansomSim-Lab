"""High-level, reversible cryptographic demo limited to manifest-owned lab files."""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .safety import SafetyError, atomic_write, canonical_within, reject_link, reject_link_components, sha256_bytes


def generate_demo_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def write_key(key: bytes) -> None:
    if len(key) != 32:
        raise SafetyError("Invalid AES-256 demo key length.")
    reject_link_components(config.RECOVERY_ROOT, config.LAB_ROOT)
    config.RECOVERY_ROOT.mkdir(parents=True, exist_ok=True)
    reject_link(config.RECOVERY_ROOT)
    content = config.KEY_LABEL + b"\n" + base64.b64encode(key) + b"\n"
    atomic_write(config.KEY_FILE, content, config.RECOVERY_ROOT)
    try:
        os.chmod(config.KEY_FILE, 0o600)
    except OSError:
        pass


def read_key() -> bytes:
    canonical_within(config.KEY_FILE, config.RECOVERY_ROOT)
    if not config.KEY_FILE.is_file():
        raise SafetyError("Demo recovery key is missing.")
    reject_link(config.KEY_FILE)
    lines = config.KEY_FILE.read_bytes().splitlines()
    if len(lines) != 2 or lines[0] != config.KEY_LABEL:
        raise SafetyError("Invalid demo recovery-key format.")
    key = base64.b64decode(lines[1], validate=True)
    if len(key) != 32:
        raise SafetyError("Invalid AES-256 demo key length.")
    return key


def encrypt_blob(plaintext: bytes, relative: str, key: bytes) -> bytes:
    if len(key) != 32:
        raise SafetyError("Invalid AES-256 demo key length.")
    nonce = secrets.token_bytes(12)
    aad = (f"{config.PROJECT_NAME}:{relative}").encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return config.ENCRYPTED_MAGIC + nonce + ciphertext


def decrypt_blob(blob: bytes, relative: str, key: bytes) -> bytes:
    if len(key) != 32:
        raise SafetyError("Invalid AES-256 demo key length.")
    minimum = len(config.ENCRYPTED_MAGIC) + 12 + 16
    if len(blob) < minimum or not blob.startswith(config.ENCRYPTED_MAGIC):
        raise SafetyError("Invalid locked-file format.")
    nonce_start = len(config.ENCRYPTED_MAGIC)
    nonce = blob[nonce_start : nonce_start + 12]
    ciphertext = blob[nonce_start + 12 :]
    aad = (f"{config.PROJECT_NAME}:{relative}").encode("utf-8")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def locked_file_is_simulator_owned(path: Path, relative: str, expected_sha256: str, key: bytes | None) -> bool:
    if key is None or not path.is_file():
        return False
    try:
        reject_link(path)
        plaintext = decrypt_blob(path.read_bytes(), relative, key)
    except Exception:
        return False
    return plaintext.startswith(config.TEST_MARKER) and sha256_bytes(plaintext) == expected_sha256

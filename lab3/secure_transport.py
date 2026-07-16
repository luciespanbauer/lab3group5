"""Authenticated encryption and configuration helpers for the UDP protocol."""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any, Mapping

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


PROTOCOL_VERSION = 1
TRANSPORT_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_PACKET_BYTES = 8192


class ConfigurationError(RuntimeError):
    """Raised when required security configuration is absent or invalid."""


class PacketError(ValueError):
    """Raised when a datagram is not a valid authenticated protocol packet."""


def load_auth_password(environ: Mapping[str, str] | None = None) -> str:
    """Load the authentication password without providing an insecure default."""

    source = os.environ if environ is None else environ
    password = source.get("INCUBATOR_AUTH_PASSWORD")
    if password is None or not password.strip():
        raise ConfigurationError(
            "INCUBATOR_AUTH_PASSWORD is required and must not be empty"
        )
    return password


def load_transport_key(environ: Mapping[str, str] | None = None) -> bytes:
    """Load and strictly validate the Base64-encoded 256-bit transport key."""

    source = os.environ if environ is None else environ
    encoded_key = source.get("INCUBATOR_TRANSPORT_KEY")
    if encoded_key is None or not encoded_key.strip():
        raise ConfigurationError("INCUBATOR_TRANSPORT_KEY is required")

    try:
        key = base64.b64decode(encoded_key.strip().encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ConfigurationError(
            "INCUBATOR_TRANSPORT_KEY must be valid Base64"
        ) from exc

    if len(key) != TRANSPORT_KEY_BYTES:
        raise ConfigurationError(
            "INCUBATOR_TRANSPORT_KEY must decode to exactly 32 bytes"
        )
    return key


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != TRANSPORT_KEY_BYTES:
        raise ConfigurationError("AES-256-GCM requires a 32-byte transport key")


def _aad(version: int) -> bytes:
    return f"incubator-udp-envelope-v{version}".encode("ascii")


def _decode_base64_field(envelope: dict[str, Any], name: str) -> bytes:
    value = envelope.get(name)
    if not isinstance(value, str):
        raise PacketError("Invalid encrypted packet")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise PacketError("Invalid encrypted packet") from exc


def encrypt_packet(payload: Mapping[str, Any], key: bytes) -> bytes:
    """Serialize and encrypt a structured payload with a fresh GCM nonce."""

    _validate_key(key)
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")
    try:
        plaintext = json.dumps(
            dict(payload),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PacketError("Payload is not JSON serializable") from exc

    nonce = get_random_bytes(GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
    cipher.update(_aad(PROTOCOL_VERSION))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    envelope = {
        "version": PROTOCOL_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    packet = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode(
        "ascii"
    )
    if len(packet) > MAX_PACKET_BYTES:
        raise PacketError("Encrypted packet is too large")
    return packet


def decrypt_packet(packet: bytes, key: bytes) -> dict[str, Any]:
    """Authenticate and decrypt an encrypted UDP envelope, failing closed."""

    _validate_key(key)
    if not isinstance(packet, bytes) or not packet or len(packet) > MAX_PACKET_BYTES:
        raise PacketError("Invalid encrypted packet")
    try:
        envelope = json.loads(
            packet.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PacketError("Invalid encrypted packet") from exc

    if not isinstance(envelope, dict) or set(envelope) != {
        "version",
        "nonce",
        "ciphertext",
        "tag",
    }:
        raise PacketError("Invalid encrypted packet")
    version = envelope.get("version")
    if type(version) is not int or version != PROTOCOL_VERSION:
        raise PacketError("Unsupported protocol version")

    nonce = _decode_base64_field(envelope, "nonce")
    ciphertext = _decode_base64_field(envelope, "ciphertext")
    tag = _decode_base64_field(envelope, "tag")
    if len(nonce) != GCM_NONCE_BYTES or len(tag) != GCM_TAG_BYTES or not ciphertext:
        raise PacketError("Invalid encrypted packet")

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
        cipher.update(_aad(version))
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise PacketError("Encrypted packet authentication failed") from exc

    try:
        payload = json.loads(
            plaintext.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PacketError("Invalid encrypted payload") from exc
    if not isinstance(payload, dict):
        raise PacketError("Encrypted payload must be a JSON object")
    return payload

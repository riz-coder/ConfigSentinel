import base64
import binascii
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings


class CollectorSecretError(Exception):
    pass


class CollectorSecretConfigurationError(CollectorSecretError):
    pass


def _key():
    try:
        value = base64.b64decode(settings.COLLECTOR_SECRET_KEY, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CollectorSecretConfigurationError("Collector secret key must be valid base64.") from exc
    if len(value) != 32:
        raise CollectorSecretConfigurationError("Collector secret key must decode to exactly 32 bytes.")
    return value


def _aad(reference):
    return f"configsentinel:collector-secret:v1:{reference}".encode("utf-8")


class LocalAgentSecretStore:
    """Agent-local encrypted store; plaintext is never written to disk."""

    def __init__(self, root=None):
        self.root = Path(root or settings.COLLECTOR_SECRET_ROOT).resolve()

    def _path(self, reference):
        if "://" not in reference:
            raise CollectorSecretError("Use an opaque credential reference such as agent-vault://device/read-only.")
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        return self.root / digest[:2] / f"{digest}.json"

    def store(self, *, reference, username, password):
        if not username or not password:
            raise CollectorSecretError("Username and password are required.")
        plaintext = json.dumps({"username": username, "password": password}, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, _aad(reference))
        payload = json.dumps({"version": 1, "nonce": base64.b64encode(nonce).decode("ascii"), "ciphertext": base64.b64encode(ciphertext).decode("ascii")}, separators=(",", ":"))
        path = self._path(reference); path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(payload)
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def retrieve(self, reference):
        path = self._path(reference)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            nonce = base64.b64decode(payload["nonce"], validate=True)
            ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
            plaintext = AESGCM(_key()).decrypt(nonce, ciphertext, _aad(reference))
            value = json.loads(plaintext.decode("utf-8"))
        except FileNotFoundError as exc:
            raise CollectorSecretError("Credential reference is not provisioned on this collector agent.") from exc
        except (KeyError, ValueError, UnicodeError, json.JSONDecodeError, InvalidTag, binascii.Error) as exc:
            raise CollectorSecretError("Credential store authentication failed.") from exc
        if not value.get("username") or not value.get("password"):
            raise CollectorSecretError("Stored credential is incomplete.")
        return value

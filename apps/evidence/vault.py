import base64
import binascii
import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings


class VaultError(Exception):
    pass


class VaultConfigurationError(VaultError):
    pass


class EvidenceIntegrityError(VaultError):
    pass


@dataclass(frozen=True)
class EncryptedObject:
    storage_key: str
    wrapped_dek: str
    wrap_nonce: str
    content_nonce: str
    plaintext_sha256: str
    ciphertext_sha256: str
    size_bytes: int


def artifact_aad(tenant_id, artifact_id) -> bytes:
    return f"configsentinel:evidence:v1:{tenant_id}:{artifact_id}".encode("ascii")


def _master_key() -> bytes:
    try:
        key = base64.b64decode(settings.EVIDENCE_MASTER_KEY, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultConfigurationError("Evidence master key must be valid base64.") from exc
    if len(key) != 32:
        raise VaultConfigurationError("Evidence master key must decode to exactly 32 bytes.")
    return key


class LocalEncryptedObjectStore:
    """Development/on-prem adapter. Plaintext is never written to disk."""

    def __init__(self, root=None):
        self.root = Path(root or settings.EVIDENCE_STORAGE_ROOT).resolve()

    def _path(self, storage_key: str) -> Path:
        if not storage_key.startswith("objects/") or ".." in storage_key or "\\" in storage_key:
            raise EvidenceIntegrityError("Invalid evidence storage key.")
        path = (self.root / storage_key).resolve()
        if self.root not in path.parents:
            raise EvidenceIntegrityError("Evidence storage path escaped its configured root.")
        return path

    def encrypt_and_store(self, *, tenant_id, artifact_id, plaintext: bytes) -> EncryptedObject:
        if len(plaintext) > settings.EVIDENCE_MAX_UPLOAD_BYTES:
            raise VaultError("Evidence file exceeds the configured upload limit.")
        aad = artifact_aad(tenant_id, artifact_id)
        dek = secrets.token_bytes(32)
        content_nonce = secrets.token_bytes(12)
        wrap_nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(dek).encrypt(content_nonce, plaintext, aad)
        wrapped_dek = AESGCM(_master_key()).encrypt(wrap_nonce, dek, aad)
        plain_hash = hashlib.sha256(plaintext).hexdigest()
        cipher_hash = hashlib.sha256(ciphertext).hexdigest()
        storage_key = f"objects/{cipher_hash[:2]}/{cipher_hash}.blob"
        path = self._path(storage_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                handle.write(ciphertext)
        except FileExistsError as exc:
            raise VaultError("Encrypted object key collision; upload was not stored.") from exc
        return EncryptedObject(
            storage_key=storage_key,
            wrapped_dek=base64.b64encode(wrapped_dek).decode("ascii"),
            wrap_nonce=base64.b64encode(wrap_nonce).decode("ascii"),
            content_nonce=base64.b64encode(content_nonce).decode("ascii"),
            plaintext_sha256=plain_hash,
            ciphertext_sha256=cipher_hash,
            size_bytes=len(plaintext),
        )

    def retrieve_and_verify(self, artifact) -> bytes:
        if artifact.purged_at:
            raise EvidenceIntegrityError("Evidence ciphertext has been governed-purged.")
        path = self._path(artifact.storage_key)
        try:
            ciphertext = path.read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError("Evidence ciphertext is missing.") from exc
        if hashlib.sha256(ciphertext).hexdigest() != artifact.ciphertext_sha256:
            raise EvidenceIntegrityError("Evidence ciphertext hash verification failed.")
        aad = artifact_aad(artifact.tenant_id, artifact.id)
        try:
            wrap_nonce = base64.b64decode(artifact.wrap_nonce, validate=True)
            content_nonce = base64.b64decode(artifact.content_nonce, validate=True)
            wrapped_dek = base64.b64decode(artifact.wrapped_dek, validate=True)
            dek = AESGCM(_master_key()).decrypt(wrap_nonce, wrapped_dek, aad)
            plaintext = AESGCM(dek).decrypt(content_nonce, ciphertext, aad)
        except (InvalidTag, ValueError, binascii.Error) as exc:
            raise EvidenceIntegrityError("Evidence authentication failed.") from exc
        if len(plaintext) != artifact.size_bytes or hashlib.sha256(plaintext).hexdigest() != artifact.plaintext_sha256:
            raise EvidenceIntegrityError("Evidence plaintext manifest verification failed.")
        return plaintext

    def purge(self, storage_key: str):
        path = self._path(storage_key)
        try:
            os.remove(path)
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError("Evidence ciphertext is already missing.") from exc

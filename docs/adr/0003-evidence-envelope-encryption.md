# ADR 0003: Envelope-encrypt evidence before object storage

## Status

Accepted for WP-EVID-01 with explicit operator approval on 2026-10-20.

## Decision

Encrypt every evidence artifact with a fresh random 256-bit data-encryption key
using AES-256-GCM. Bind the tenant UUID, artifact UUID, and crypto version as
authenticated additional data. Wrap each data key with a separately configured
256-bit master key using AES-256-GCM and a second random 96-bit nonce.

Store ciphertext under its SHA-256 address. Store the wrapped data key, nonces,
plaintext/ciphertext hashes, size, and immutable workflow metadata in PostgreSQL.
Never write plaintext to the local object store or include filenames/content in
audit logs. Browser downloads use opaque attachment names and `no-store`.

## Why

Per-artifact keys limit nonce/key reuse and prepare the model for a production
KMS that wraps keys without exposing its KEK. AEAD detects ciphertext, wrapped
key, tenant, artifact, or version substitution. Separate hashes support manifest
checks and external custody verification without replacing AEAD authentication.

## Consequences

- Loss of the master key permanently destroys access; governed backup and
  recovery testing are mandatory before customer data is accepted.
- The environment-key provider and local filesystem adapter are development or
  single-node/on-prem foundations, not the final multi-node production backend.
- Key rotation/re-wrapping and a KMS/S3 adapter remain required before hosted
  production use. Existing ciphertext must never be decrypted merely to rotate
  a wrapping key.
- Uploads are bounded and kept in memory so plaintext is not spooled to disk.
- Uploaded content remains untrusted and opaque; malware scanning/CDR is not
  implemented in this package, so downloads are forced attachments.

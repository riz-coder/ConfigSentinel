# Evidence vault operations

## Key setup

Generate a 32-byte base64 master key on the deployment host:

```powershell
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Set the result as `CONFIGSENTINEL_EVIDENCE_MASTER_KEY` through a secrets manager
or protected environment injection. Do not commit it, print it in application
logs, reuse a Django secret, or place it in an evidence artifact. Production
startup fails when the key is absent. A malformed key fails each upload/download
closed.

Back up the key separately under dual control. Test recovery using synthetic
artifacts. Database or ciphertext backup without the corresponding key is not
recoverable; key backup without both database manifest and ciphertext is also
insufficient.

## Storage and privacy

The local adapter writes only authenticated ciphertext beneath
`CONFIGSENTINEL_EVIDENCE_STORAGE_ROOT`. Compose mounts a persistent named volume.
It is suitable for Windows development and a controlled single-node deployment,
but not HA object storage. Production SaaS requires an reviewed KMS/S3-compatible
adapter, residency decision, versioning, access logging, and coordinated backup.

Allowed initial types are PDF, JSON, DOCX, XLSX, JPEG, PNG, CSV, and plain text.
Files are not parsed or previewed. They are untrusted input, returned only as
opaque attachments, and do not become accepted merely through upload.

## Review, expiry, retention, and holds

- Upload begins `UNDER_REVIEW` and is linked to one approved exact mapping.
- The uploader cannot review their own artifact. A compliance lead or auditor
  must verify integrity and explicitly accept or reject it.
- Accepted evidence becomes effectively `STALE` after its approved freshness
  window. Run `python manage.py mark_stale_evidence` on a schedule to persist and
  audit the stale transition.
- No purge is allowed without a configured expired retention period. Any active
  hold blocks purge regardless of age. Manifests and custody events survive a
  permitted ciphertext purge.

Do not accept customer evidence until malware handling, KMS recovery, encrypted
off-host backup, restore drill, retention policy, and residency review are signed
off for the deployment.

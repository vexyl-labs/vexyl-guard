# Signed Policy Bundles

Vexyl policy delivery is moving away from public, installer-embedded logic and toward authenticated bundles served by the control plane.

## Current Preview

The Worker exposes:

```text
GET /v1/policy.bundle.json
```

The route requires either the ingest bearer token or the admin bearer token. It returns a short-lived bundle with:

- `payload`: readable policy data for the enrolled client.
- `payload_b64`: the canonical payload bytes encoded as base64url.
- `signature`: an RSA-SHA-256 signature over `payload_b64`.
- `alg`: `RS256` for the public-key preview path.
- `kid`: the signing key identifier used to select a local public key.
- `expires_at`: a five-minute expiry timestamp.
- response policy values such as scoring threshold, scoring window, block TTL, sync interval, and mutation weighting.

This gives the preview control plane a real integrity boundary: enrolled clients reject stale or modified policy bundles before applying server-delivered response policy. The Worker keeps the private signing key as a secret; installed agents only need the public verification key.

Shared deny entries are not created directly by source or behavior rollups. An operator must approve a source signal, stage a TTL-bound promotion, and publish that promotion before the source appears in `policy.deny_ips`. Revoking a published promotion removes its owned deny entry from the next bundle.

## Agent Enrollment

Signed bundle sync is enabled when the agent config includes:

```text
VEXYL_API_URL=https://api.vexyl.dev
VEXYL_API_TOKEN=<enrolled ingest token>
VEXYL_POLICY_BUNDLE_ENABLED=auto
VEXYL_POLICY_PUBLIC_KEY_DIR=/etc/vexyl/policy-keys.d
VEXYL_POLICY_PUBLIC_KEY_FILE=/etc/vexyl/policy-signing-public.pem
VEXYL_POLICY_REVOKED_KEYS_FILE=/etc/vexyl/revoked-policy-keys.txt
VEXYL_POLICY_KEY_ID=vexyl-policy-dev-1
```

With a public key configured, the agent refuses unsigned policy fallback. For `RS256`, the bundle `kid` selects `/etc/vexyl/policy-keys.d/<kid>.pem`. The single `VEXYL_POLICY_PUBLIC_KEY_FILE` path remains as a compatibility fallback when `kid` matches `VEXYL_POLICY_KEY_ID`.

If bundle retrieval or signature verification fails, the daemon keeps running with its existing local state and logs the failure.

For manual testing:

```bash
sudo vexyl-guard sync
sudo vexyl-guard status
sudo vexyl-guard verify-policy /path/to/policy.bundle.json
```

## Security Boundary

Public distribution must not put a signing secret on customer machines. Vexyl policy delivery now supports asymmetric signatures for that reason:

1. Keep the private key in Worker/release infrastructure secrets.
2. Ship only verification public keys to installed agents.
3. Sign policy bundles, installer manifests, and package checksums.
4. Support key rotation with `kid` and overlapping trust windows.
5. Make the installer verify a detached signature before replacing local binaries.

`HS256` HMAC verification remains in the agent only for existing private-preview hosts. New installs should use `RS256`.

## Key Rotation

The public installer now uses signed release metadata to install policy verification material:

```text
/downloads/policy-keys/TRUSTED_KEYS
/downloads/policy-keys/<kid>.pem
/downloads/revoked-policy-keys.txt
```

Rotation process:

1. Generate the next RSA keypair and keep the private key out of the repo.
2. Publish the new public key at `/downloads/policy-keys/<new-kid>.pem`.
3. Add both old and new key IDs to `TRUSTED_KEYS`.
4. Regenerate `SHA256SUMS` and sign it with the current release signing key.
5. Let hosts update trust material before changing the Worker `POLICY_KEY_ID` and private key secret.
6. After the overlap window, add the retired key ID to `revoked-policy-keys.txt`, regenerate the manifest, and deploy.

The agent rejects any policy bundle whose `kid` appears in `VEXYL_POLICY_REVOKED_KEY_IDS` or `VEXYL_POLICY_REVOKED_KEYS_FILE`, even if the corresponding public key is still present on disk.

## Release Manifest Verification

The public installer downloads:

```text
/downloads/SHA256SUMS
/downloads/SHA256SUMS.sig
/downloads/RELEASE.json
/downloads/release-signing-public.pem
```

It verifies the detached signature with the embedded Vexyl public key before trusting the checksum manifest, then verifies `downloads/vexyl-guard.sh` before replacing `/usr/local/sbin/vexyl-guard`.

After first install, operators can update through the installed agent:

```bash
sudo vexyl-guard upgrade
```

The upgrade command uses `/etc/vexyl/release-signing-public.pem` to verify the manifest signature, verifies every downloaded asset against the signed manifest, evaluates `RELEASE.json`, refreshes policy trust material, and only then replaces the local agent binary.

Release metadata gates upgrades with:

- `version`: target agent version.
- `min_upgrade_from`: oldest agent allowed to use the release.
- `rollback_allowed`: whether a lower signed version may be installed when the operator explicitly sets `VEXYL_UPGRADE_ALLOW_DOWNGRADE=true`.
- `rollback_policy`: operator-readable rollback posture.

Same-version releases refresh trust material but skip binary replacement unless `VEXYL_UPGRADE_FORCE=true` or the target binary is missing. Downgrades are refused by default even when the manifest is valid.

# Signed Intelligence Updates

Vexyl Guard can refresh its local defensive AI threat records from an authenticated Vexyl API endpoint. This channel complements the bundled public baseline. It does not download executable code, firewall rules, model instructions, jailbreak payloads, malware, or raw customer data.

## Trust Boundary

Each update is an `RS256` envelope signed by a Vexyl policy key already trusted by the host. The client verifies the key ID, revocation list, signature, schema, validity window, record count, canonical record hash, defensive data shape, and monotonic sequence before activation.

The private signing key remains in Vexyl release infrastructure. Installed hosts receive public keys only:

```text
/etc/vexyl/policy-keys.d/<kid>.pem
/etc/vexyl/revoked-policy-keys.txt
```

An authenticated download is not enough by itself. A bundle must also have a valid signature from a non-revoked local trust anchor. HTTPS redirects are refused so the bearer token cannot be forwarded to another origin.

## Activation And Recovery

Verified records are loaded into a temporary SQLite database first. Vexyl Guard then snapshots the active database and replaces intelligence tables in one transaction. Redacted runtime-event history is not imported from the bundle and is not replaced during activation or rollback.

The client maintains a monotonic sequence high-water mark. Older bundles are rejected. Reusing a sequence with different records is also rejected. A bundle with the current sequence and identical record hash may refresh signed metadata and expiry without replacing tables.

The last-known-good database defaults to:

```text
/var/lib/vexyl/ai_threats.sqlite.lkg
```

The local gateway attempts recovery from that snapshot only when the active database fails its SQLite integrity check. Manual rollback is explicit and does not lower the trusted sequence high-water mark.

## Enable Automatic Updates

The package installs the updater disabled. First place an enrolled Vexyl agent or API bearer token in a root-only file. This token is never printed by the CLI or returned in status output.

```bash
sudo bash -c 'read -rsp "Enrolled Vexyl token: " token; printf "\n"; install -m 0600 /dev/null /etc/vexyl/intel-update.token; printf "%s\n" "$token" > /etc/vexyl/intel-update.token'
sudo systemctl enable --now vexyl-intel-update.timer
```

The prompt does not echo the token. Do not place it in shell history, source control, issue reports, or support bundles.

Run an immediate update and inspect the active version:

```bash
sudo systemctl start vexyl-intel-update.service
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite intel-status
sudo systemctl status vexyl-intel-update.timer
```

Configuration lives in `/etc/vexyl/intel-update.conf`. The default timer runs every six hours with a randomized delay to avoid synchronized fleet traffic.

## Manual Verification And Recovery

Verify a downloaded envelope without changing the database:

```bash
sudo vexyl threat verify-intel-bundle /path/to/ai-intel.bundle.json
```

Apply a verified local bundle:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite \
  apply-intel-bundle /path/to/ai-intel.bundle.json
```

Restore the previous signed intelligence tables:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite rollback-intel --yes
```

Recover only when the active SQLite database is corrupt:

```bash
sudo vexyl threat --db /var/lib/vexyl/ai_threats.sqlite recover-intel --yes
```

If a scheduled update fails, the currently active records remain in use. Expired metadata is reported as stale; it is not silently treated as a fresh update. Operators should investigate authentication, clock accuracy, network access, endpoint availability, and local trust material before replacing any files.

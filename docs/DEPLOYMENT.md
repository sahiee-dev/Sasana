# Archeion — Deployment Guide

Archeion is the Sasana authority sealing server. It appends a cryptographically signed
`CHAIN_SEAL` event to completed agent sessions, upgrading their evidence class to
`AUTHORITATIVE_EVIDENCE`. This guide covers how to deploy it safely inside your
security perimeter.

---

## 1. What Data Leaves the Container — and What Does Not

This section answers the question a compliance consultant or risk officer will ask
before recommending Archeion to a client.

**Archeion receives:** A completed session JSONL file sent by an internal agent process
via `POST /seal`. This file contains SHA-256 hashes of prompts, responses, and tool
arguments — not the raw content. No prompt text, no model responses, no tool arguments
ever leave the agent process.

**Archeion returns:** The same session JSONL with one appended event — the `CHAIN_SEAL`
— which includes a timestamp, the session's root hash, and Archeion's Ed25519 public key.
Nothing else leaves the container.

**The private key never leaves the container.** It is generated inside the container on
first start, stored in a named Docker volume (or injected via environment variable), and
never transmitted to any endpoint.

**No external network calls.** Archeion makes zero outbound connections at runtime. It
does not call home, does not check for updates, does not log to a third-party service.
The container can run with egress blocked entirely.

**Network access model:**
```
Agent process  ──POST /seal──▶  Archeion (internal network only)
                                      │
                          No outbound connections
```

**What to tell a risk officer:** "Archeion is a local signing authority. It receives
SHA-256 hashes, appends a cryptographic signature, and returns. No raw AI content
touches it, and nothing leaves the network perimeter."

---

## 2. Key Generation and Initial Setup

Archeion needs one Ed25519 private key. There are two ways to provide it.

### Option A — Environment variable (recommended for production)

Generate a key outside the container and inject it at runtime:

```bash
# Generate the key
python3 -c "
import base64, os
key = os.urandom(32)
print('ARCHEION_PRIVATE_KEY=' + base64.b64encode(key).decode())
"
```

Store the output value in your secrets manager (HashiCorp Vault, AWS Secrets Manager,
Azure Key Vault, or equivalent). Never write it to a `.env` file checked into version
control.

At deploy time, inject it:
```bash
export ARCHEION_PRIVATE_KEY="<value from secrets manager>"
docker compose up -d
```

### Option B — Persistent volume (acceptable for internal deployments)

If no `ARCHEION_PRIVATE_KEY` is set, Archeion auto-generates a key on first start and
stores it at `/home/archeion/.archeion/server_key.b64` inside the container. The
`docker-compose.yml` mounts a named volume at that path so the key persists across
container restarts.

**Back this volume up immediately after first start:**
```bash
docker run --rm \
    -v archeion-keys:/data \
    alpine \
    tar czf - /data > archeion_key_backup_$(date +%Y%m%d).tar.gz
```

Store this backup offline, encrypted, in the same location as your CA root material.

### Retrieve the active public key

After starting Archeion, retrieve the public key to pin in your verification workflows:

```bash
curl http://localhost:8747/pubkey | python3 -m json.tool
# {
#   "pubkey": "<base64 Ed25519 public key>",
#   "algorithm": "ed25519",
#   "encoding": "base64"
# }
```

Pin this value wherever you run `sasana verify --trust-key <pubkey>`. Record it alongside
your key backups — it is the fingerprint that lets you verify which key sealed which
sessions.

---

## 3. Key Lifecycle Model

**Read this before writing a key rotation policy.**

The Archeion server key is not an API key. It has fundamentally different rotation
semantics, and treating it like an API key will break your audit trail.

### Why the key is not rotatable on a schedule

When Archeion seals a session, the resulting JSONL file embeds the server's public key
in the `CHAIN_SEAL` event. That public key is part of the cryptographic proof. Any
verifier using `--trust-key` will compare the embedded key against the pinned key.

If you rotate the Archeion key, all sessions sealed before the rotation can only be
verified against the **old** key — not the new one. To a verifier (or an auditor's
script) using the new key as the trust anchor, those old sessions will show
`COMPROMISED`. They are not compromised — but the tool cannot know that without being
told which key was active when each session was sealed.

**The correct mental model: Archeion's key is like a CA root certificate, not a
service credential.**

A CA root is:
- Generated once
- Kept for the lifetime of everything it signed
- Backed up to offline storage
- Rotated only if compromised — and even then, the old key is retained for verification
  of pre-rotation material

An API key is:
- Rotated on a schedule (quarterly, annually)
- Abandoned after rotation
- Used only for authentication, not for signing durable artefacts

Your key rotation policy should say "rotate only on compromise, retain forever."

### What to tell a DR team asking about key rotation policy

> "The Archeion server key is a signing authority, not a service credential. It is
> retained for the lifetime of the sealed sessions it produced. Key rotation is a
> break-glass procedure, not a scheduled operation. If the key is ever compromised,
> we rotate it and retain the old key for re-verification of prior sessions."

### If a key compromise occurs

1. Rotate the key immediately (generate a new one, redeploy Archeion).
2. **Do not delete the old key.** Move it to a clearly labelled offline store:
   `archeion_key_RETIRED_YYYYMMDD.b64`
3. Re-verification of sessions sealed before the rotation must use the old key:
   ```bash
   sasana verify <session.jsonl> --trust-key <old-pubkey>
   ```
4. Sessions sealed after the rotation use the new key.
5. Document the rotation date. Auditors will ask which key applies to which date range.

### Key storage requirements

| Requirement | Why |
|---|---|
| Back up immediately after generation | Container volume loss = permanent loss of ability to verify sealed sessions |
| Store offline, encrypted | Same threat model as a CA root |
| Never delete while sessions within retention period are signed with it | Deletion makes sealed sessions unverifiable |
| Record the public key alongside the backup | Needed for `--trust-key` in verification |

---

## 4. docker-compose.yml and Network Isolation

### Start Archeion

```bash
# Clone the repo or copy Dockerfile and docker-compose.yml to your server
git clone https://github.com/sahiee-dev/Sasana.git
cd Sasana

# Set the private key (Option A)
export ARCHEION_PRIVATE_KEY="<value from secrets manager>"

# Build and start
docker compose up -d --build

# Verify it's running
curl http://localhost:8747/health
# {"status":"ok","version":"1.0.0","pubkey":"<base64>"}
```

### Network isolation

The `docker-compose.yml` binds Archeion to `127.0.0.1:8747` — localhost only. It is
on an internal Docker network (`archeion-internal`) that is not exposed to the internet.

**To allow an agent container to reach Archeion,** add it to the same network:

```yaml
# In your agent's docker-compose service definition:
services:
  my-agent:
    networks:
      - archeion-internal

networks:
  archeion-internal:
    external: true   # References the network created by Archeion's compose file
```

**Do not:**
- Expose port 8747 on `0.0.0.0`
- Add Archeion to a public-facing load balancer
- Allow inbound connections from outside your network perimeter

Archeion has no authentication. Any process that can reach `POST /seal` can submit a
session for sealing. Network isolation is your only access control layer.

### Reverse proxy (optional, for TLS)

If agent processes need to reach Archeion across a network boundary (e.g., different
subnets), put nginx or Caddy in front with TLS termination:

```nginx
server {
    listen 443 ssl;
    server_name archeion.internal;

    ssl_certificate     /etc/ssl/certs/archeion.crt;
    ssl_certificate_key /etc/ssl/private/archeion.key;

    location / {
        proxy_pass http://127.0.0.1:8747;
    }
}
```

Use your internal PKI for the TLS certificate. Do not expose this to the public internet.

---

## 5. Environment Variable Reference

| Variable | Required | Description |
|---|---|---|
| `ARCHEION_PRIVATE_KEY` | No | Base64-encoded 32-byte Ed25519 private key. If set, takes priority over all key files. Inject from a secrets manager. |
| `ARCHEION_KEY_FILE` | No | Path to a key file containing base64-encoded raw private key bytes. Overrides the default path `~/.archeion/server_key.b64`. |

If neither variable is set, Archeion generates a key on first start and stores it at
`/home/archeion/.archeion/server_key.b64` inside the container. The `docker-compose.yml`
maps a named volume to that path for persistence.

---

## 6. Health Check and Monitoring

### Endpoint

```
GET /health
```

Response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "pubkey": "<base64 Ed25519 public key>"
}
```

The response includes the active public key so monitoring systems can alert if the key
changes unexpectedly (e.g., Archeion restarted with a different key file). If the pubkey
in `/health` no longer matches the pubkey you pinned with `--trust-key`, something changed.

### Recommended monitoring checks

1. **Liveness:** `/health` returns 200. Already wired into the Dockerfile `HEALTHCHECK`.

2. **Key change detection:** Periodically compare `/health`.pubkey against the expected
   public key. Alert if they diverge — it means Archeion restarted with a different key,
   which will cause all previously-pinned verifications to fail.
   ```bash
   EXPECTED_PUBKEY="<your pinned pubkey>"
   ACTUAL=$(curl -s http://localhost:8747/health | python3 -c "import sys,json; print(json.load(sys.stdin)['pubkey'])")
   [ "$ACTUAL" = "$EXPECTED_PUBKEY" ] || echo "ALERT: Archeion pubkey changed"
   ```

3. **Seal throughput:** Count `POST /seal` responses. A drop to zero when agent sessions
   are running means the sealing pipeline is broken.

---

## 7. Sealing a Session

Once Archeion is running, submit a completed session for sealing:

```bash
# Via the CLI (requires sasana installed in the agent environment)
sasana seal <session.jsonl> --server http://localhost:8747

# The sealed file is written back to <session.jsonl> by default.
# To write to a different file:
sasana seal <session.jsonl> --server http://localhost:8747 --out sealed_<session.jsonl>
```

### Verify the sealed session

```bash
# Without key pinning (trusts whichever key is embedded in the seal)
sasana verify <session.jsonl>

# With key pinning (recommended — rejects seals from any other key)
sasana verify <session.jsonl> --trust-key <archeion-pubkey>

# Using the Rust binary (zero Python dependency — for forensic environments)
./sasana-rs/target/release/sasana verify <session.jsonl> --trust-key <archeion-pubkey>
```

Expected output for a correctly sealed session:
```
Sasana Verifier v1.0.0
File     : session.jsonl
Session  : <session-id>
Events   : 7
Evidence : AUTHORITATIVE_EVIDENCE

[1/5] Structural validity  ... PASS
[2/5] Sequence integrity   ... PASS
[3/5] Hash chain integrity ... PASS
[4/5] Session completeness ... PASS
[5/5] Seal signature       ... PASS

Result: INTACT ✅
```

---

## 8. What to Include in a Client Deliverable

If you are a compliance consultant preparing documentation for a client, the key facts
to include are:

**Data handling:**
- Archeion receives SHA-256 hashes of agent session events — no raw content
- No data leaves the client's network perimeter
- The signing key is generated and held inside the client's infrastructure

**Evidence produced:**
- Sessions sealed by Archeion carry evidence class `AUTHORITATIVE_EVIDENCE`
- The seal is a cryptographic signature by an authority server that the agent process
  has no access to — the agent cannot forge its own seal
- Sealed sessions can be verified offline, without Archeion running, using the embedded
  public key

**Key management:**
- The Archeion signing key is retained for the lifetime of sealed sessions
- Rotation is a break-glass procedure, not a scheduled rotation
- The client should back up the key to offline storage and treat it as CA root material

**Regulatory mapping:**
- EU AI Act Article 12: AUTHORITATIVE_EVIDENCE satisfies the tamper-evident logging
  requirement for high-risk AI systems
- SOC 2 CC7.2: sealed sessions provide cryptographically verifiable evidence of
  AI system monitoring
- HIPAA §164.312(b): the hash-chain audit log satisfies audit control requirements;
  raw PHI is never recorded

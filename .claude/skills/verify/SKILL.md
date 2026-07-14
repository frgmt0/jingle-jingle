---
name: verify
description: Build and drive the jingle CLI end-to-end in an isolated temp vault to verify changes at the binary surface.
---

# Verifying jingle

Build: `cargo build --release` → binary at `target/release/jingle`.

Isolate every run so the real vault is never touched — jingle honors two env vars:

```sh
export JINGLE_DATA_DIR=$(mktemp -d)/data
export JINGLE_KEYFILE=$(mktemp -d)/key
J=target/release/jingle
```

## Core drive (exercises most of the surface)

```sh
$J init
$J add github --service github.com --username bot@example.com --generate --length 32
$J list && $J show github                       # values must render as [REDACTED]
printf 'otpauth://totp/X:b?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' | $J set github totp --stdin
$J totp github                                  # 6-digit code + expiry
$J exec -s github=GH_PASS -- sh -c 'echo "len=${#GH_PASS} leak=[$JINGLE_KEYFILE]"'   # len=32 leak=[]
$J lock github
$J exec -s github=GH_PASS -- true               # must exit 5, print nothing from the child
$J exec --confirm-locked github -s github=GH_PASS -- true
$J audit                                        # chain: OK
```

## Worthwhile probes

- Corrupt a middle byte of `$JINGLE_DATA_DIR/vault.jingle` → any command exits 4; restore from `vault.jingle.bak`.
- TOTP cross-check against Python stdlib (`hmac`+`base32decode`, period 30, 6 digits) — codes must match.
- `--json` on any failing command → error JSON on stderr, empty stdout.
- `copy` in this headless container → exit 6 (expected: no X11).
- `chmod 644 $JINGLE_KEYFILE` → commands refuse; restore with 600.
- Exit codes are contractual: 0/1/2/3/4/5/6 (see README).

## Gotchas

- `exec` needs `--` before the child command (clap `last = true`).
- Secrets never go on argv; pipe via `--stdin`. A bare positional secret is a usage error — that's by design, not a bug.
- The burst tripwire counts distinct entries across ALL egress commands in the last 60 s of the audit log, so earlier accesses in the same probe session count toward the >5 threshold.
- Stdout of `list`/`show` must never contain secret material; `tests/redaction.rs` is the authoritative check (`cargo test --test redaction`).

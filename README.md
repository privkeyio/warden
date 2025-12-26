# Warden

Policy engine for Bitcoin custody operations.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Policy DSL](#policy-dsl)
- [API](#api)
- [Security](#security)
- [Development](#development)

---

## Installation

```bash
cargo install --path warden-cli
```

Requires Rust 1.75+.

**From source:**

```bash
git clone https://github.com/privkeyio/warden
cd warden
cargo build --release
./target/release/warden --help
```

---

## Quick Start

```bash
# Validate a policy
warden policy validate -f policy.yaml

# Create and activate
warden policy create -f policy.yaml
warden policy activate <id>

# Set up address lists
warden whitelist create approved-vendors
warden whitelist add approved-vendors bc1q...

# Dry-run evaluation
warden evaluate --wallet treasury-hot-1 --destination bc1q... --amount 5000000

# Start API server
warden serve --port 3000
```

Data stored at `~/.local/share/warden`.

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `warden policy list` | List all policies |
| `warden policy create -f <file>` | Create policy from YAML |
| `warden policy validate -f <file>` | Validate policy syntax |
| `warden policy activate <id>` | Activate a policy |
| `warden policy deactivate <id>` | Deactivate a policy |
| `warden policy get <id>` | Get policy details |
| `warden policy explain <id>` | Human-readable summary |
| `warden evaluate --wallet <w> --destination <d> --amount <a>` | Dry-run evaluation |
| `warden whitelist create <name>` | Create address whitelist |
| `warden whitelist add <name> <addr>` | Add address to whitelist |
| `warden blacklist create <name>` | Create address blacklist |
| `warden blacklist add <name> <addr>` | Add address to blacklist |
| `warden serve` | Start REST API server |

---

## Policy DSL

Cedar-inspired YAML syntax with first-match evaluation:

```yaml
version: "1.0"
name: "treasury-policy"

rules:
  - id: "small-whitelisted"
    conditions:
      source_wallets: ["treasury-hot-*"]
      destination:
        in_whitelist: "approved-vendors"
      amount:
        max_sats: 10000000
    action: ALLOW

  - id: "block-sanctioned"
    conditions:
      destination:
        in_blacklist: "ofac-sanctioned"
    action: DENY

  - id: "large-transfers"
    conditions:
      amount:
        min_sats: 100000000
    action: REQUIRE_APPROVAL
    approval:
      quorum: 2
      from_groups: ["treasury-signers"]
      timeout_hours: 24

default_action: DENY
```

**Conditions:**

| Field | Description |
|-------|-------------|
| `source_wallets` | Glob patterns for wallet IDs |
| `destination.addresses` | Explicit address list |
| `destination.in_whitelist` | Must be in named whitelist |
| `destination.in_blacklist` | Must be in named blacklist |
| `destination.not_in_blacklist` | Must not be in blacklist |
| `amount.min_sats` | Minimum amount |
| `amount.max_sats` | Maximum amount |
| `time_window.days_of_week` | Allowed days |
| `time_window.hours_utc` | Allowed hours |

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/v1/policies` | GET | List policies |
| `/v1/policies` | POST | Create policy |
| `/v1/policies/{id}` | GET | Get policy |
| `/v1/policies/{id}` | PUT | Update policy |
| `/v1/policies/{id}` | DELETE | Delete policy |
| `/v1/policies/{id}/activate` | POST | Activate policy |
| `/v1/policies/{id}/deactivate` | POST | Deactivate policy |
| `/v1/policies/evaluate` | POST | Dry-run evaluation |
| `/v1/transactions/authorize` | POST | Authorize transaction |
| `/v1/whitelists` | GET/POST | Manage whitelists |
| `/v1/whitelists/{name}/addresses` | POST/DELETE | Manage addresses |
| `/v1/blacklists` | GET/POST | Manage blacklists |

---

## Security

| Feature | Implementation |
|---------|----------------|
| Storage | redb embedded database |
| Code Safety | Pure Rust, `#![forbid(unsafe_code)]` |
| Evaluation | Deterministic, bounded execution |
| Signing | Pluggable backend trait (FROST compatible) |

---

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace

# Debug logging
RUST_LOG=debug cargo run --bin warden -- <command>
```

---

## License

AGPL-3.0

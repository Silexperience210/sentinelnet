# SentinelNet v0.1.0

**Incentivized Decentralized Watchtower Protocol for the Bitcoin Lightning Network**

> *Always Watching. Never Sleeping.*

---

## What it does

SentinelNet protects Lightning Network channels against:

- **Replacement Cycling Attacks** (CVE-2023-40231/32/33/34) — detects when an HTLC disappears from mempool before confirmation and immediately re-broadcasts the claim transaction
- **CLTV Expiry Attacks** — monitors timelock expiry and pre-emptively defends channels
- **Zombie/Force-Close scenarios** — via the Shadow Broadcast mechanism

When a defense succeeds, the sentinel automatically sends a **keysend bounty** to the protected node's LND as payment for the service.

---

## Architecture

```
Bitcoin Knots (RPC)
      │
      ▼
MempoolWatcher ──event──► DefenseEngine ──defense──► BountyProcessor
      │                         │                          │
   polling                  broadcast                  keysend via
  every 5s                  claim tx                   LND REST API
                                │
                          HtlcStore (sled)
                                │
                          GossipMesh (TCP)
                                │
                          Other Sentinel Nodes
```

---

## Requirements

- Rust 1.75+
- Bitcoin Knots or Core with RPC enabled
- LND node (for keysend bounty payments)

---

## Build

```bash
git clone ...
cd sentinelnet
cargo build --release
```

---

## Setup

### 1. Configure Bitcoin Knots RPC

Add to `bitcoin.conf`:
```ini
server=1
rpcuser=bitcoinrpc
rpcpassword=your_strong_password
rpcallowip=127.0.0.1
```

### 2. Get your LND macaroon

```bash
# Get admin macaroon as hex
xxd -p -c 256 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
```

### 3. Generate config

```bash
./sentinel init
# Edit config.toml with your settings
```

### 4. Start the daemon

```bash
./sentinel start
# or with custom config:
./sentinel --config /path/to/config.toml start
```

---

## Registering an HTLC

Protected nodes register their HTLCs with the sentinel via the REST API:

```bash
curl -X POST http://localhost:9000/register \
  -H "Content-Type: application/json" \
  -d '{
    "txid": "abc123...",
    "vout": 0,
    "claim_txs": [
      "0200000001...",  // base fee (~10 sat/vbyte)
      "0200000001...",  // 2x fee
      "0200000001...",  // 5x fee
      "0200000001..."   // 10x fee (last resort)
    ],
    "protected_node_pubkey": "02abcdef...",
    "cltv_expiry": 840000,
    "amount_sats": 100000
  }'
```

**The `claim_txs` array should contain pre-signed versions of your HTLC claim transaction at different fee rates.** The sentinel will escalate through them if lower fees fail to confirm.

---

## Monitoring

```bash
# Status
curl http://localhost:9000/status

# All watched HTLCs
curl http://localhost:9000/htlcs

# Logs
RUST_LOG=sentinelnet=debug ./sentinel start
```

---

## Gossip Mesh

Connect to other SentinelNet nodes by adding their address to `config.toml`:

```toml
[gossip]
peers = ["192.168.1.2:9001", "sentinel.example.com:9001"]
```

Sentinels share:
- Attack alerts (immediate broadcast when replacement cycling detected)
- Defense announcements (who defended what)
- Watch requests (redundant watching across mesh)

---

## Economic Model

| Event | Payment |
|---|---|
| HTLC watched (passive) | `availability_fee_sats_per_hour` × hours |
| Replacement cycling defense | `min_bounty` × 2.0 multiplier |
| CLTV expiry defense (<3 blocks) | `min_bounty` × 3.0 multiplier |
| Fast response (base fee tier) | × 1.5 speed bonus |

---

## Security Notes

- The sentinel **never holds private keys** — it only broadcasts pre-signed transactions provided by the protected node
- Sled database is local only — no data sent to external services
- Gossip is unauthenticated in v0.1 — add noise/noise-protocol in production

---

## Roadmap

- [ ] v0.2: Nostr-based sentinel discovery (kind:30200)
- [ ] v0.3: Cryptographic gossip authentication (Noise protocol)
- [ ] v0.4: BOLT-14 proposal draft
- [ ] v0.5: LND plugin for automatic HTLC registration

---

*Released as open research — no rights reserved. Contribute at will.*

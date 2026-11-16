# Keryx Stratum bridge — H15/H16 update

Bridge for the official Keryx miner's Stratum v3 mining and private inference protocol, updated for H15/H16 with strikes displayed by delegated escrow key. Bounded Windows/RTX 5080 runs passed mining, a private request/response and the audits actually drawn under both H15 (isolated testnet chain) and H16 (public testnet). See the [inference validation record](docs/validation/h15-h16-inference-20261111.md) for exact versions, evidence and limits.

Consensus source: [keryx-node a69a1a08](https://github.com/Keryx-Labs/keryx-node/tree/a69a1a08c0e49181eecafd6128695dd0d7c667e3). Wire reference: [keryx-miner v0.6.1 / 4167e409](https://github.com/Keryx-Labs/keryx-miner/tree/4167e409e3217580ca257ca3eb35792260b7e40f). Bridge base: `d9fe31ff91337922c4c593d3717f01f002518a23`.

This bridge serves one explicitly configured payout address and its delegated escrow key. It is intended for an operator's authenticated workers. It does not implement a public pool's user accounts, share accounting, payouts or independent escrow keys per worker.

Changes:

- Verify each H15/H16 PoM v5 share with pinned official consensus code, including the H16 pad parameters, before crediting or submitting it. Reject duplicate, unauthorized, mismatched-model and proof-less submissions.
- Follow the official miner's difficulty conversion and accept a network-valid block even when the pool share target is harder. PoM job admission does not wait for the legacy soft inference challenge, which the official miner ignores under PoM.
- Poll node obligations automatically; dispatch `mining.ai_request`, seal/sign `mining.ai_response`, and handle `mining.ai_opening` / `mining.ai_opening_result`. Requests and audits are not enabled manually one by one.
- Verify trace, residual, recurrent and phased attention opening proofs before signing them. Persist encrypted requests, owning worker identities, signed envelopes and verified attention roots before sending/retrying.
- Show current and lifetime strikes, suspensions and pending burns by the bridge's escrow key, mapped through its verified payout delegation to the node's service identity. Show unavailable/stale observations explicitly.
- Remove miner-supplied application names from consensus coinbase data; require strict payout/worker authorization, bounded frames/connections, deadlines and TLS outside loopback. Monitoring uses separate loopback HTTP routers.

## Build

Use Go **1.26.11** or a later patched version, a C compiler (the inherited Kaspa dependency uses CGO), and Rust **1.96.1**. Windows builds require a MinGW GCC on PATH. No miner, node, IPFS daemon or wallet is started by these commands.

```powershell
./build.ps1
```

On Linux:

```sh
./make_release.sh
```

Both executables and `SHA256SUMS` are written to `bin/`. Cargo consensus dependencies are pinned by commit and `verifier/Cargo.lock`.

## Configure

Edit `cmd/keryxbridge/config.yaml`. File paths resolve relative to the configuration file.

1. Generate a **new dedicated escrow key** using the official tooling. The private key previously committed to this repository is public/compromised; this version rejects its fingerprint. Never reuse a personal payout wallet key as the bridge escrow key.
2. Set `payout_address`, `escrow_key_file`, and the offline delegation certificate produced by `keryx-cli delegate-escrow <escrow_pubkey> <payout_address>`. Startup verifies the address checksum/network and the certificate's Schnorr signature before connecting workers.
3. Generate a separate high-entropy worker token for each worker. `worker_auth_file` is a JSON object mapping a worker name to the lowercase SHA256 digest of its token. Use `<payout_address>.<worker_name>` as the miner login and its token as `--pool-password`. Worker names use 1–64 ASCII letters, digits, `_` or `-`.
4. Restrict the secret files and state directory to the operator's service account. On Windows apply NTFS ACLs; the POSIX file mode is not an ACL substitute.
5. Set the helper path. Optionally set `verifier_sha256` to the locally approved helper hash. Start the bridge only when the operator is ready for node submissions and real mining.

For example, the **structure** of `worker-tokens.json` is `{"rig01":"<64 lowercase hex characters: SHA256 of its private token>"}`. No example token, private key, live address or operational certificate is supplied.

The official miner added direct `stratum+ssl://` and `stratum+tls://` connections in [commit dfca69de](https://github.com/Keryx-Labs/keryx-miner/commit/dfca69de0c03d330153788b1b31391e5f3d95e79), after the v0.6.1-PoM release used for the H15/H16 inference runs. This bridge already has a compatible TLS 1.3 listener. See [direct TLS setup](docs/stratum-tls.md). Older miner builds need an authenticated encrypted tunnel exposing a loopback TCP endpoint, or a local TLS forwarder. Non-loopback bridge listeners require a TLS certificate and key; node RPC and monitoring must remain on loopback.

## Observe

`print_stats` includes the escrow key, delegated service identity, consecutive misses, lifetime strikes, pending burns and suspension DAA. The loopback health listener exposes:

- `GET /bridge/strikes`: node observations, exact burn amount as a decimal sompi string, observation time and availability.
- `GET /bridge/service`: queue/audit counts and service readiness, without prompts, answers, private keys or worker tokens.
- `GET /bridge/pubkey`: public escrow key and delegated service identity.
- `GET /readyz`: 503 while the node, obligations, verifier or service observations are unavailable.

Prometheus exposes `ks_escrow_service_status{escrow_key,service_identity,field}`. Check `available` and `observed_unix` before interpreting the other gauges. An unsynced node cannot replace a previous strike observation with an available zero. Node penalties belong to the payout-script identity; multiple delegated keys sharing that identity necessarily share its penalty history. A model declaration admits jobs; full consensus proofs, signed responses and audited openings establish the work.

## Migration and limits

This branch intentionally fails closed with the old sample configuration. Keep the original node, miner and personal keys outside this checkout. Preserve the service state file and each owning miner's trace store across reconnects and upgrades.

H15/H16 are not the block-task fork: `block_task_activation` is unscheduled on both pinned networks. The existing experimental v4 code is not enabled as a shortcut for H15.

The inherited legacy automatic claim loop is **not started**. Its 36,000-block assumptions and optimistic mempool accounting are unsuitable as a claim authority for the current 792,000-block service-bond escrow regime. This update signs only zero-input/zero-output service publications; recovering locked escrow requires a separately validated current claim tool and the correct dedicated key. No escrow or wallet funds were spent to validate this branch.

A SHA256 manifest verifies local artifact bytes against a trusted manifest. An untrusted remote miner can report any hash or name. This update does not claim to force remote execution of an official bridge binary; that would require a separately specified trust/attestation mechanism. Correctness comes from authenticated routing, verified delegation, consensus proofs and node-observed obligations.

See [validation and recovery notes](docs/h15-h16.md) before qualification or deployment.

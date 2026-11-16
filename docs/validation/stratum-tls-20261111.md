# Official miner direct TLS validation — 2026-11-11

Result: **PASS for direct TLS 1.3 connections and bounded H16 testnet mining**, with both `stratum+ssl://` and `stratum+tls://`. This is separate from the earlier [H15/H16 private-inference runs](h15-h16-inference-20261111.md).

## Source and environment

- Same clean bridge runtime source as the full-cycle runs: `1a06691a83d7e4c770fbe28196e32d99800f60b8`. Its existing TLS 1.3 listener required no wire/proof or trust-policy change. The follow-up adds setup instructions, configuration comments and these validation records.
- Official miner source `dfca69de0c03d330153788b1b31391e5f3d95e79`, the upstream TLS commit immediately following v0.6.1-PoM. Both the miner executable and its Rust CUDA plugin were built together from unchanged source, using a generated local Cargo lock followed by a locked release build. The unchanged official-release inference DLL was used with the existing test models.
- Windows, RTX 5080, Gemma-4-12B-abliterated, official node v1.6.7-PoM on public testnet-10, normal consensus parameters and full PoM verification.
- Dedicated test-only data/state/identity copied from the stopped H16 trial. A bounded solo bootstrap renewed the stale public testnet tip; those blocks are excluded below. The public peer briefly disconnected during setup. The final bootstrap required a stable synced observation before handoff; the bridge kept `mine_when_not_synced: false` throughout.
- A temporary localhost DNS certificate was signed by an isolated private CA and trusted only through `--pool-ca-file`. Windows system trust was not changed. No certificate verification was disabled and no plaintext fallback was added.

## Executed results

| Check | Result |
| --- | --- |
| Official miner `stratum+ssl://localhost:27555` → authenticated TLS bridge → official H16 node | 31 distinct accepted blocks |
| Official miner `stratum+tls://localhost:27555` alias → same listener/node | 47 distinct accepted blocks |
| Union, independently retrieved from node and header-hash checked | 78 blocks, DAA 549,271–549,336 |
| Official miner without the private CA | PASS: `UnknownIssuer`, no TLS session established |
| Official miner using literal IP while certificate covers only `localhost` | PASS: `NotValidForName`, no TLS session established |
| Trusted CA connection | PASS: negotiated TLS 1.3 |
| Plaintext and TLS 1.2 sent to TLS 1.3 listener | PASS: refused |
| Wrong worker token, cross-payout login, unknown worker over TLS | PASS: Unauthorized (24) |
| Readiness, public identity, strikes and service endpoints | PASS |
| Supplemental transport/auth/status checks, before and after mining | 24 PASS (12 distinct, twice) |
| Full bridge logs after cleanup | No race/panic report |
| Owned process closure receipts | All closed |

Both official miner logs reported `TLS session established with localhost:27555`. The two block sets are disjoint. The bridge still verified each full proof before submission and the official node accepted the blocks. Node acceptance is not a claim of selected-chain rewards.

First checked block: `9971bef93c484b8bec82206915617386fdbbcd5f97ccb56a7a275044d6ca55a0`, DAA 549,271.

Last checked block: `df8ec088d4bdb87ecc1b258ee752996c4f4b1fb492366c352ddb870295db055c`, DAA 549,336.

## Artifact identities and limits

- Race-instrumented bridge SHA256: `8a971fa2c2cb8345e167f8921237cbf2154bfd53ad7c5cd95b922b1082638228` (`vcs.modified=false`).
- Source-built official miner SHA256: `79ddbb7cfd41f62c707f6f70745fb60e818547b301a6b1d9af0000aadd0d3d4e`.
- Matching CUDA plugin SHA256: `add30e2c8ee410e1ff8377e89c59e6c953f7723b13585b142ba87d4aa3332c4e`.
- Generated miner Cargo lock SHA256: `fcf54447cc2ebb9285fad5cba2a31a018d45e51133b4399c50f51a343d317717`; the upstream repository does not commit this lock.

Failed setup attempts were retained locally and are not counted as TLS passes: mixing the source-built miner with a previous-release Rust plugin crashed before CLI/TLS; the first generated test leaf certificate omitted its Authority Key Identifier and was rejected by strict certificate validation; an initial short bootstrap lost peer connectivity/readiness before the bridge listener opened. Rebuilding the matching plugin, correcting the test certificate and waiting for stable node synchronization resolved these setup issues. No bridge trust, sync or proof check was relaxed.

This validates local direct-TLS interoperability with the pinned official miner and one model/GPU. It does not qualify public DNS, certificate issuance/renewal, remote routing, every OS/client combination or another full private-inference run over TLS. The inference/audit evidence remains the separately pinned H15/H16 record. No personal/mainnet funds were spent, no escrow claim was executed, and all owned test processes were stopped. Secrets, certificates' private keys and raw logs remain outside the repository.

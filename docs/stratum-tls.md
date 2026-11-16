# Direct TLS connections from the official miner

The official miner introduced `stratum+ssl://` and its `stratum+tls://` alias in [dfca69de0c03d330153788b1b31391e5f3d95e79](https://github.com/Keryx-Labs/keryx-miner/commit/dfca69de0c03d330153788b1b31391e5f3d95e79). The v0.6.1-PoM release at `4167e409` predates that change; use a build containing the TLS commit for direct TLS. The bridge listener already supports TLS 1.3 with no extra Stratum framing, ALPN or miner patch.

## Configure the bridge

Keep the existing dedicated payout/delegation, worker-token file and verifier settings. To serve TLS, set these fields in the bridge configuration:

```yaml
stratum_port: 0.0.0.0:5555
tls_cert_file: secrets/bridge-fullchain.pem
tls_key_file: secrets/bridge-tls.key
```

File paths are relative to the configuration file. The certificate must cover the hostname used by the miner in its DNS SAN, or the literal IP in its IP SAN. Supply the leaf certificate followed by its intermediate certificates in `tls_cert_file`. Protect the private key with the service account's file permissions. Node RPC, health and Prometheus listeners remain on loopback. The TLS listener also works on loopback for local validation.

## Connect the miner

For a certificate issued by a public CA trusted by the miner's bundled roots:

```powershell
./keryx-miner.exe -s stratum+ssl://bridge.example.net:5555 `
  -a "<configured-payout-address>.rig01" `
  --pool-password "$env:KERYX_WORKER_TOKEN"
```

For a private CA, add `--pool-ca-file ./bridge-ca.pem`. This file contains the trusted CA certificate(s), not the bridge's private key. The miner still checks the server name, chain and certificate validity. `stratum+tls://` selects the same encrypted transport. `stratum+tcp://` selects plaintext and should only target a trusted loopback tunnel/forwarder when remote encryption is needed; a TLS bridge listener does not fall back to plaintext.

TLS authenticates and encrypts the connection to the bridge. The existing worker token and payout checks still authenticate the miner. The local helper SHA256 pin is independent of TLS and does not attest which program an untrusted remote miner runs.

## Validation boundary

The [direct TLS validation](validation/stratum-tls-20261111.md) passed on 2026-11-11 with unchanged official miner source `dfca69de`: 31 node-confirmed H16 testnet blocks over `stratum+ssl://`, 47 over `stratum+tls://`, both official-client certificate refusals and 24 supplemental transport/auth/status checks. TLS 1.3 was negotiated with a private CA supplied only to the client.

The H15/H16 full-cycle record uses the preceding official release over loopback TCP. The TLS test did not execute another private inference request and does not change the source or evidence of those inference runs. A local certificate test is not a public DNS/certificate-renewal or remote deployment qualification.

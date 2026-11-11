//! Local, bounded protocol verifier. Secrets never appear in a request or response.
mod audit;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use keryx_consensus_core::{
    collateral::{
        miner_key, opening_signature_message, responder_signature_message, verify_escrow_delegation,
    },
    config::params::{
        H15_ACTIVATION_DAA, H16_ACTIVATION_DAA, TESTNET_H15_ACTIVATION_DAA,
        TESTNET_H16_ACTIVATION_DAA, pom_v5_pad_tiles, service_tiers,
    },
    pom::{PomProof, pom_block_seed_h14, pom_pow_value_h3},
    pom_v5::{v5_pad_seed, verify_pom_proof_v5_container},
    tx::ScriptPublicKey,
};
use keryx_inference::{AiRequestPayload, AiResponder, AiResponsePayload, TraceCommitment};
use keryx_verifiable_inference::{answer, opening, shape};
use secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Read, Write};

const MAX_LINE: u64 = 6 * 1024 * 1024;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Request {
    op: String,
    network: String,
    key_file: String,
    payout: String,
    cert: String,
    payload: String,
    request: String,
    text: String,
    trace: String,
    body: String,
    response: String,
    seed_block: String,
    path: Vec<u64>,
    draw_seed: String,
    signed_response: String,
    previous_root: String,
    pieces: u32,
    pph: String,
    timestamp: u64,
    nonce: u64,
    daa: u64,
    target_le: String,
    proof: String,
}

struct Identity {
    secret: [u8; 32],
    pair: Keypair,
    pubkey: [u8; 32],
    network: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

fn h32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|_| "invalid hex")?
        .try_into()
        .map_err(|_| "expected 32 bytes".into())
}
fn raw(s: &str, limit: usize) -> Result<Vec<u8>, String> {
    if s.len() > limit * 2 {
        return Err("input exceeds limit".into());
    }
    hex::decode(s).map_err(|_| "invalid hex".into())
}
fn init(r: &Request) -> Result<(Identity, Value), String> {
    let prefix = match r.network.as_str() {
        "mainnet" => keryx_addresses::Prefix::Mainnet,
        "testnet" => keryx_addresses::Prefix::Testnet,
        _ => return Err("network must be mainnet or testnet".into()),
    };
    let address = keryx_addresses::Address::try_from(r.payout.as_str())
        .map_err(|_| "invalid payout checksum")?;
    if address.prefix != prefix
        || address.version != keryx_addresses::Version::PubKey
        || address.payload.len() != 32
    {
        return Err("payout must be a Schnorr P2PK address on the configured network".into());
    }
    let mut key_text =
        std::fs::read_to_string(&r.key_file).map_err(|_| "cannot read escrow key file")?;
    let secret = h32(key_text.trim())?;
    // Reject the private key shipped in the upstream repository without ever displaying it.
    if Sha256::digest(secret).as_slice()
        == hex::decode(include_str!("../compromised-key.sha256").trim())
            .map_err(|_| "invalid compromised-key fingerprint")?
            .as_slice()
    {
        key_text.clear();
        return Err("the escrow key published in the upstream repository is compromised; generate a new dedicated key".into());
    }
    key_text.clear();
    let sk = SecretKey::from_slice(&secret).map_err(|_| "invalid escrow secret")?;
    let pair = Keypair::from_secret_key(SECP256K1, &sk);
    let pubkey = pair.x_only_public_key().0.serialize();
    let cert: [u8; 64] = raw(&r.cert, 64)?
        .try_into()
        .map_err(|_| "invalid delegation certificate length")?;
    let mut script = vec![0x20];
    script.extend_from_slice(&address.payload);
    script.push(0xac);
    if !verify_escrow_delegation(0, &script, &pubkey, &cert) {
        return Err("delegation certificate does not bind this payout to this escrow key".into());
    }
    let identity = miner_key(&ScriptPublicKey::new(0, script.into())).to_string();
    let models: Vec<_> = service_tiers(true)
        .iter()
        .enumerate()
        .map(|(tier, t)| json!({"tier":tier,"model":hex::encode(t.model_id)}))
        .collect();
    Ok((
        Identity {
            secret,
            pair,
            pubkey,
            network: r.network.clone(),
        },
        json!({"ok":true,"pubkey":hex::encode(pubkey),"identity":identity,"models":models}),
    ))
}

fn request_payload(
    r: &Request,
    id: &Identity,
) -> Result<(AiRequestPayload, keryx_inference::OpenedRequest), String> {
    let req = AiRequestPayload::deserialize(&raw(&r.payload, 65536)?)
        .ok_or("invalid AiRequest payload")?;
    if !req.is_private() {
        return Err("H15/H16 requires a sealed request".into());
    }
    let opened = keryx_inference::open_request(&req, &id.secret)
        .map_err(|_| "request cannot be opened by this escrow key")?;
    Ok((req, opened))
}

fn check(r: Request, id: &Identity) -> Result<Value, String> {
    match r.op.as_str() {
        "proof" => {
            let (h15, h16) = if id.network == "mainnet" {
                (H15_ACTIVATION_DAA, H16_ACTIVATION_DAA)
            } else {
                (TESTNET_H15_ACTIVATION_DAA, TESTNET_H16_ACTIVATION_DAA)
            };
            if r.daa < h15 {
                return Err("this verifier requires H15 PoM v5".into());
            }
            let raw = raw(&r.proof, 2 * 1024 * 1024)?;
            let proof = PomProof::from_wire_bytes(&raw).map_err(|_| "invalid PoM encoding")?;
            if proof.to_wire_bytes() != raw || proof.task.is_some() {
                return Err("noncanonical proof or inactive block task".into());
            }
            let pph = h32(&r.pph)?;
            let target = h32(&r.target_le)?;
            let tier = service_tiers(true)
                .get(proof.tier as usize)
                .ok_or("invalid PoM tier")?;
            let seed = pom_block_seed_h14(&pph, r.timestamp, r.nonce);
            let pad = v5_pad_seed(proof.tier, &tier.model_id, &tier.root);
            verify_pom_proof_v5_container(
                seed,
                &proof,
                tier.chunks,
                &tier.root,
                &pad,
                pom_v5_pad_tiles(proof.tier, r.daa >= h16),
                &target,
                |s| pom_pow_value_h3(s, &pph),
            )
            .map_err(|_| "PoM v5 proof verification failed")?;
            Ok(
                json!({"ok":true,"tier":proof.tier,"model":hex::encode(tier.model_id),"final_state":proof.final_state,"pow_le":hex::encode(proof.pow_value)}),
            )
        }
        "request" => {
            let (req, opened) = request_payload(&r, id)?;
            let tier = service_tiers(true)
                .iter()
                .position(|t| t.model_id == req.model_id)
                .ok_or("unsupported model")?;
            Ok(
                json!({"ok":true,"model":hex::encode(req.model_id),"tier":tier,"prompt":B64.encode(&opened.prompt),"prompt_len":opened.prompt.len(),"max_tokens":req.max_tokens,"reward":req.inference_reward.to_string()}),
            )
        }
        "answer" => {
            let (req, opened) = request_payload(&r, id)?;
            let trace = TraceCommitment::from_bytes(&raw(&r.trace, 73)?)
                .ok_or("invalid trace commitment")?;
            let plain = raw(&r.body, 65536)?;
            let (text, ids) = answer::decode(&plain).ok_or("answer lacks generated token IDs")?;
            let reported = B64.decode(r.text).map_err(|_| "invalid answer base64")?;
            if text != reported
                || trace.stage != 2
                || trace.tokens_root.is_none()
                || trace.n_pos < trace.n_prompt
                || ids.len() != (trace.n_pos - trace.n_prompt) as usize
                || !shape::shape_ok(
                    opened.prompt.len() as u32,
                    text.len() as u32,
                    req.max_tokens,
                    trace.n_prompt,
                    trace.n_pos,
                )
            {
                return Err("answer, token count or trace shape mismatch".into());
            }
            let generated: Vec<u8> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
            if trace.tokens_root != Some(*blake3::hash(&generated).as_bytes()) {
                return Err("generated token commitment mismatch".into());
            }
            let request = h32(&r.request)?;
            let body = keryx_inference::seal_response(&opened.response_key, &request, &plain);
            if body.len() > keryx_inference::MAX_AI_RESPONSE_PRIVATE_BODY_LEN {
                return Err("sealed answer exceeds consensus size limit".into());
            }
            let mut cid = [0u8; 34];
            cid[..2].copy_from_slice(&[0x12, 0x20]);
            cid[2..].copy_from_slice(&Sha256::digest(&body));
            let end = r.daa.checked_add(1000).ok_or("DAA overflow")?;
            let mut payload = AiResponsePayload::new(request, end, cid, ids.len() as u32)
                .with_private_body(body)
                .with_trace(trace);
            let msg = responder_signature_message(&payload.signed_bytes());
            let signature = SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest(msg), &id.pair)
                .serialize();
            payload.responder = Some(AiResponder {
                escrow_pubkey: id.pubkey,
                signature,
            });
            let wire = payload.serialize();
            if AiResponsePayload::deserialize(&wire).as_ref() != Some(&payload) {
                return Err("noncanonical response".into());
            }
            Ok(json!({"ok":true,"payload":hex::encode(wire)}))
        }
        "opening" => {
            let body = raw(&r.body, 2 * 1024 * 1024)?;
            let response = h32(&r.response)?;
            let seed_block = h32(&r.seed_block)?;
            let mut hash = blake2b_simd::Params::new().hash_length(32).to_state();
            hash.update(b"KeryxTraceDrawV1");
            hash.update(&seed_block);
            hash.update(&response);
            let seed = hash.finalize();
            if hex::encode(seed.as_bytes()) != r.draw_seed {
                return Err("node draw does not match retained chain block".into());
            }
            let (req, _) = request_payload(&r, id)?;
            let tier = service_tiers(true)
                .iter()
                .position(|t| t.model_id == req.model_id)
                .ok_or("unsupported audit model")?;
            let rules = keryx_consensus_core::config::params::trace_rules(
                tier as u8, true, true, true, true,
            )
            .ok_or("no audit rules")?;
            let resp = AiResponsePayload::deserialize(&raw(&r.signed_response, 65536)?)
                .ok_or("invalid retained response")?;
            let responder = resp
                .responder
                .as_ref()
                .ok_or("unsigned retained response")?;
            if resp.request_hash != h32(&r.request)?
                || responder.escrow_pubkey != id.pubkey
                || !keryx_consensus_core::collateral::verify_responder_signature(
                    &responder.escrow_pubkey,
                    &responder.signature,
                    &resp.signed_bytes(),
                )
            {
                return Err("retained response identity/signature mismatch".into());
            }
            let trace = resp.trace.as_ref().ok_or("retained response lacks trace")?;
            if r.path.len() > 64 || r.pieces == 0 || r.pieces > 15 {
                return Err("invalid node draw metadata".into());
            }
            let previous = if r.previous_root.is_empty() {
                None
            } else {
                Some(h32(&r.previous_root)?)
            };
            let bodies = unbundle(&body)?;
            let mut payloads = Vec::new();
            let mut attention_root = None;
            let mut seen = 0u32;
            for body in bodies {
                if body.len() < 33 || body[1..33] != response || !opening::is_audit_body(&body) {
                    return Err("invalid opening or response binding".into());
                }
                let piece = audit::opening_body_piece(&body) as u32;
                if piece & r.pieces == 0 {
                    continue;
                }
                if seen & piece != 0 {
                    return Err("duplicate audit piece".into());
                }
                seen |= piece;
                if let Some(path) = opening::attn_path(&body) && path != r.path {
                    return Err("attention path mismatch".into());
                }
                let seed_bytes: [u8; 32] = seed.as_bytes().try_into().unwrap();
                let next = audit::verify(
                    &body,
                    &rules,
                    trace,
                    resp.request_hash,
                    response,
                    seed_bytes,
                    &r.path,
                    previous,
                )?;
                if piece == 2 {
                    attention_root = next;
                }
                let mut seeded =
                    opening::seeded(&body, &seed_block).ok_or("cannot seed opening")?;
                if !opening::is_audit_body(&seeded) {
                    return Err("invalid seeded opening".into());
                }
                let sig = SECP256K1
                    .sign_schnorr_no_aux_rand(
                        &Message::from_digest(opening_signature_message(&seeded)),
                        &id.pair,
                    )
                    .serialize();
                seeded.extend_from_slice(&id.pubkey);
                seeded.extend_from_slice(&sig);
                payloads.push(hex::encode(seeded));
            }
            if payloads.is_empty() {
                return Err("no currently required opening piece".into());
            }
            Ok(
                json!({"ok":true,"payloads":payloads,"attention_root":attention_root.map(hex::encode)}),
            )
        }
        _ => Err("unsupported operation".into()),
    }
}

// Official miner v0.6.1 trace_seq::bundle wire layout, with additional bounds.
fn unbundle(body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if body.first() != Some(&0xB0) {
        return Ok(vec![body.to_vec()]);
    }
    let n = *body.get(1).ok_or("truncated bundle")? as usize;
    if n == 0 || n > 16 {
        return Err("invalid bundle count".into());
    }
    let mut offset = 2usize;
    let mut bodies = Vec::new();
    for _ in 0..n {
        let len = u32::from_le_bytes(
            body.get(offset..offset + 4)
                .ok_or("truncated bundle length")?
                .try_into()
                .unwrap(),
        ) as usize;
        if len > opening::MAX_BODY_LEN {
            return Err("opening exceeds consensus size limit".into());
        }
        offset += 4;
        let end = offset.checked_add(len).ok_or("bundle overflow")?;
        bodies.push(
            body.get(offset..end)
                .ok_or("truncated bundle body")?
                .to_vec(),
        );
        offset = end;
    }
    if offset != body.len() {
        return Err("trailing bundle bytes".into());
    }
    Ok(bodies)
}

fn main() {
    let mut identity = None;
    let mut reader = io::stdin().lock();
    let mut out = io::BufWriter::new(io::stdout().lock());
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .unwrap_or(0);
        if n == 0 || n as u64 > MAX_LINE {
            break;
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
                let r: Request = serde_json::from_slice(&line).map_err(|_| "invalid request")?;
                if r.op == "init" {
                    if identity.is_some() {
                        return Err("identity is already initialized".into());
                    }
                    let (id, value) = init(&r)?;
                    identity = Some(id);
                    Ok(value)
                } else {
                    check(r, identity.as_ref().ok_or("identity is not initialized")?)
                }
            }))
            .unwrap_or_else(|_| Err("verifier rejected input".into()))
            .unwrap_or_else(|e| json!({"ok":false,"error":e}));
        if writeln!(out, "{result}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}

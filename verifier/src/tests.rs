use super::*;
use keryx_consensus_core::collateral::{escrow_delegation_message, verify_responder_signature};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    dir: PathBuf,
    init: Request,
}
impl Fixture {
    fn new() -> Self {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/runtime-tests");
        std::fs::create_dir_all(&parent).unwrap();
        let dir = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        // Fixed keys are confined to offline test fixtures and never used for mining.
        let escrow = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[7; 32]).unwrap());
        let payout = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[9; 32]).unwrap());
        let address = keryx_addresses::Address::new(
            keryx_addresses::Prefix::Testnet,
            keryx_addresses::Version::PubKey,
            &payout.x_only_public_key().0.serialize(),
        );
        let cert = SECP256K1.sign_schnorr_no_aux_rand(
            &Message::from_digest(escrow_delegation_message(
                &escrow.x_only_public_key().0.serialize(),
            )),
            &payout,
        );
        std::fs::write(dir.join("escrow.key"), hex::encode([7; 32])).unwrap();
        Self {
            init: Request {
                op: "init".into(),
                network: "testnet".into(),
                payout: address.to_string(),
                cert: cert.to_string(),
                key_file: dir.join("escrow.key").to_string_lossy().into_owned(),
                ..Default::default()
            },
            dir,
        }
    }
    fn identity(&self) -> Identity {
        init(&self.init).unwrap().0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.dir.join("escrow.key"));
        let _ = std::fs::remove_dir(&self.dir);
    }
}

#[test]
fn delegation_is_checked_against_payout_and_network() {
    let mut fixture = Fixture::new();
    let (_, metadata) = init(&fixture.init).unwrap();
    assert_eq!(metadata["ok"], true);
    assert_ne!(metadata["identity"], metadata["pubkey"]);
    fixture.init.network = "mainnet".into();
    assert!(init(&fixture.init).is_err());
    fixture.init.network = "testnet".into();
    fixture.init.cert.replace_range(..2, "00");
    assert!(init(&fixture.init).is_err());
}

#[test]
fn invalid_payout_and_key_files_are_refused() {
    let mut fixture = Fixture::new();
    fixture.init.payout.push('q');
    assert!(init(&fixture.init).is_err());
    fixture.init.payout.pop();
    std::fs::write(&fixture.init.key_file, "invalid secret").unwrap();
    assert!(init(&fixture.init).is_err());
}

fn sealed_answer(id: &Identity) -> (Request, keryx_inference::PrivateRequestSecret) {
    let (payload, secret) = keryx_inference::seal_request(
        service_tiers(true)[2].model_id,
        16,
        100_000_000,
        1,
        b"Test prompt",
        &[id.pubkey],
    )
    .unwrap();
    let ids: Vec<u32> = vec![42, 43];
    let tokens: Vec<_> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
    let trace = TraceCommitment {
        trace_root: [5; 32],
        n_prompt: 4,
        n_pos: 6,
        stage: 2,
        tokens_root: Some(*blake3::hash(&tokens).as_bytes()),
    };
    (
        Request {
            op: "answer".into(),
            payload: hex::encode(payload.serialize()),
            request: hex::encode([8; 32]),
            text: B64.encode(b"answer"),
            body: hex::encode(answer::encode(b"answer", &ids)),
            trace: hex::encode(trace.to_bytes()),
            daa: TESTNET_H16_ACTIVATION_DAA,
            ..Default::default()
        },
        secret,
    )
}

#[test]
fn private_answer_roundtrip_has_valid_signature_and_request_binding() {
    let fixture = Fixture::new();
    let id = fixture.identity();
    let (request, secret) = sealed_answer(&id);
    let reply = check(request, &id).unwrap();
    let wire = hex::decode(reply["payload"].as_str().unwrap()).unwrap();
    let response = AiResponsePayload::deserialize(&wire).unwrap();
    let signer = response.responder.unwrap();
    assert!(verify_responder_signature(
        &signer.escrow_pubkey,
        &signer.signature,
        &response.signed_bytes()
    ));
    let plain = keryx_inference::open_response(
        &secret,
        &[8; 32],
        &id.pubkey,
        response.private_body.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(
        answer::decode(&plain).unwrap(),
        (&b"answer"[..], vec![42, 43])
    );
    assert!(
        keryx_inference::open_response(
            &secret,
            &[6; 32],
            &id.pubkey,
            response.private_body.as_deref().unwrap()
        )
        .is_err()
    );
    assert!(
        !wire
            .windows(b"answer".len())
            .any(|window| window == b"answer")
    );
}

#[test]
fn answer_rejects_text_or_token_commitment_tampering() {
    let fixture = Fixture::new();
    let id = fixture.identity();
    let (mut request, _) = sealed_answer(&id);
    request.text = B64.encode(b"changed text");
    assert!(check(request, &id).is_err());
    let (mut request, _) = sealed_answer(&id);
    request.body = hex::encode(answer::encode(b"answer", &[44, 43]));
    assert!(check(request, &id).is_err());
    let (mut request, _) = sealed_answer(&id);
    let mut trace = hex::decode(&request.trace).unwrap();
    trace[40] = 1;
    request.trace = hex::encode(trace);
    assert!(check(request, &id).is_err());
}

#[test]
fn request_rejects_an_unlisted_recipient() {
    let fixture = Fixture::new();
    let id = fixture.identity();
    let another = keryx_inference::escrow_pubkey_of(&[3; 32]).unwrap();
    let (payload, _) = keryx_inference::seal_request(
        service_tiers(true)[2].model_id,
        16,
        100_000_000,
        1,
        b"private",
        &[another],
    )
    .unwrap();
    let request = Request {
        op: "request".into(),
        payload: hex::encode(payload.serialize()),
        ..Default::default()
    };
    assert!(check(request, &id).is_err());
}

#[test]
fn proof_gate_and_malformed_proofs_fail_closed() {
    let fixture = Fixture::new();
    let id = fixture.identity();
    for daa in [
        TESTNET_H15_ACTIVATION_DAA - 1,
        TESTNET_H15_ACTIVATION_DAA,
        TESTNET_H16_ACTIVATION_DAA - 1,
        TESTNET_H16_ACTIVATION_DAA,
    ] {
        let request = Request {
            op: "proof".into(),
            daa,
            proof: hex::encode([0; 73]),
            ..Default::default()
        };
        assert!(
            check(request, &id).is_err(),
            "invalid proof accepted at DAA {daa}"
        );
    }
}

#[test]
fn opening_bundle_bounds_and_trailing_bytes_are_enforced() {
    let body = vec![1, 2, 3];
    let mut bundle = vec![0xB0, 1];
    bundle.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bundle.extend_from_slice(&body);
    assert_eq!(unbundle(&bundle).unwrap(), vec![body]);
    bundle.push(0);
    assert!(unbundle(&bundle).is_err());
    for bad in [
        &[0xB0][..],
        &[0xB0, 0],
        &[0xB0, 17],
        &[0xB0, 1, 3, 0, 0, 0, 1],
    ] {
        assert!(unbundle(bad).is_err());
    }
}

#[test]
fn unknown_json_fields_are_not_silently_ignored() {
    assert!(
        serde_json::from_str::<Request>(r#"{"op":"init","payout_override":"attacker"}"#).is_err()
    );
}

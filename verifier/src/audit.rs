//! Opening checks adapted from Keryx node a69a1a08, consensus/core/src/collateral.rs.
//! Keep this small adapter in sync when changing the pinned consensus dependency.
use keryx_consensus_core::config::params::TraceRules;
use keryx_inference::TraceCommitment;
const PIECE_TRACE: u8 = 1;
const PIECE_ATTN: u8 = 2;
const PIECE_RECUR: u8 = 4;
const PIECE_RESID: u8 = 8;
struct AttnProgress {
    path: Vec<u64>,
    root: [u8; 32],
}
struct TraceAudit {
    request_hash: [u8; 32],
    trace_root: [u8; 32],
    n_prompt: u32,
    n_pos: u32,
    attn: Option<AttnProgress>,
}

// Arguments correspond to the consensus response, draw and parent-phase bindings.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    body: &[u8],
    rules: &TraceRules,
    trace: &TraceCommitment,
    request: [u8; 32],
    response: [u8; 32],
    seed: [u8; 32],
    path: &[u64],
    previous: Option<[u8; 32]>,
) -> Result<Option<[u8; 32]>, &'static str> {
    let attn = if path.is_empty() {
        None
    } else {
        Some(AttnProgress {
            path: path.to_vec(),
            root: previous.ok_or("missing verified parent phase root")?,
        })
    };
    let audit = TraceAudit {
        request_hash: request,
        trace_root: trace.trace_root,
        n_prompt: trace.n_prompt,
        n_pos: trace.n_pos,
        attn,
    };
    match opening_body_piece(body) {
        2 => match attn_opening_valid(rules, &audit, &seed, &response, body)? {
            keryx_verifiable_inference::chain::AttnStep::Done => Ok(None),
            keryx_verifiable_inference::chain::AttnStep::Next { root, .. } => Ok(Some(root)),
        },
        4 => {
            recur_opening_valid(rules, &audit, &seed, &response, body)?;
            Ok(None)
        }
        8 => {
            resid_opening_valid(rules, &audit, &seed, &response, body)?;
            Ok(None)
        }
        _ => {
            trace_opening_valid(rules, &audit, &seed, &response, body)?;
            Ok(None)
        }
    }
}

fn trace_opening_valid(
    rules: &keryx_consensus_core::config::params::TraceRules,
    audit: &TraceAudit,
    seed: &[u8; 32],
    txid: &[u8; 32],
    body: &[u8],
) -> Result<(), &'static str> {
    use keryx_verifiable_inference::{chain, draw::POINTS, opening::Opening, prefix, verify};
    let Some(opening) = Opening::decode(body) else {
        return Err("malformed body");
    };
    if &opening.response_txid != txid {
        return Err("response id mismatch");
    }
    if opening.points.len() != POINTS as usize {
        return Err("point count");
    }
    let mut resp = verify::ResponseCtx {
        trace_root: audit.trace_root,
        n_prompt: audit.n_prompt,
        n_pos: audit.n_pos,
    };
    if let Some(cc) = &rules.chain {
        let (Some(pc), Some(pp)) = (&rules.prefix, &opening.prefix) else {
            return Err("stage-2 part missing");
        };
        if opening.resid.is_some() {
            return Err("residual point in the trace piece");
        }
        resp.trace_root = split_trace_root(rules, audit, &opening.roots)?;
        if opening.links.len() != opening.points.len()
            || opening.experts.len() != opening.points.len()
        {
            return Err("link count");
        }
        for (i, (p, (tok, link))) in opening.points.iter().zip(&opening.links).enumerate() {
            let ids = opening.experts.get(i).and_then(Option::as_ref);
            if chain::verify_chain_point(&rules.ctx, cc, &resp, seed, i as u32, p, *tok, link, ids)
                .is_err()
            {
                return Err(if i == 0 { "point 0" } else { "point 1" });
            }
        }
        return chain::verify_chain_prefix_point(
            &rules.ctx,
            cc,
            pc,
            &resp,
            seed,
            &audit.request_hash,
            pp,
        )
        .map(|_| ())
        .map_err(|_| "prefix point");
    }
    if opening.resid.is_some() {
        return Err("stage-2 opening before its rule");
    }
    for (i, p) in opening.points.iter().enumerate() {
        if verify::verify_point(&rules.ctx, &resp, seed, i as u32, p).is_err() {
            return Err(if i == 0 { "point 0" } else { "point 1" });
        }
    }
    match (&rules.prefix, &opening.prefix) {
        (None, _) => Ok(()),
        (Some(_), None) => Err("prefix point missing"),
        (Some(pc), Some(p)) => {
            prefix::verify_prefix_point(&rules.ctx, pc, &resp, seed, &audit.request_hash, p)
                .map(|_| ())
                .map_err(|_| "prefix point")
        }
    }
}

/// The piece an opening body, seeded or not, proves.
/// Piece an opening body proves.
pub fn opening_body_piece(body: &[u8]) -> u8 {
    use keryx_verifiable_inference::opening::{
        VERSION_ATTN, VERSION_RECUR, VERSION_RESID, inner_body,
    };
    match inner_body(body).and_then(|b| b.first().copied()) {
        Some(VERSION_ATTN) => PIECE_ATTN,
        Some(VERSION_RECUR) => PIECE_RECUR,
        Some(VERSION_RESID) => PIECE_RESID,
        _ => PIECE_TRACE,
    }
}

/// Position root a stage-2 piece is checked against: the split position root under the attention
/// rule, the trace root otherwise.
fn split_trace_root(
    rules: &keryx_consensus_core::config::params::TraceRules,
    audit: &TraceAudit,
    roots: &Option<([u8; 32], [u8; 32])>,
) -> Result<[u8; 32], &'static str> {
    match (rules.attention, roots) {
        (true, Some((pos_root, seq_root))) => {
            if keryx_verifiable_inference::seq::trace_root(pos_root, seq_root) != audit.trace_root {
                return Err("trace root split");
            }
            Ok(*pos_root)
        }
        (true, None) => Err("sequence root missing"),
        (false, Some(_)) => Err("sequence root before its rule"),
        (false, None) => Ok(audit.trace_root),
    }
}

/// Checks that a residual opening body proves the residual point of `audit` under `seed`.
fn resid_opening_valid(
    rules: &keryx_consensus_core::config::params::TraceRules,
    audit: &TraceAudit,
    seed: &[u8; 32],
    txid: &[u8; 32],
    body: &[u8],
) -> Result<(), &'static str> {
    use keryx_verifiable_inference::{
        chain,
        opening::{ResidOpening, inner_body},
        verify,
    };
    let op = inner_body(body)
        .as_deref()
        .and_then(ResidOpening::decode)
        .ok_or("malformed residual body")?;
    if &op.response_txid != txid {
        return Err("response id mismatch");
    }
    let cc = rules
        .chain
        .as_ref()
        .ok_or("residual piece before its rule")?;
    let trace_root = split_trace_root(rules, audit, &op.roots)?;
    let resp = verify::ResponseCtx {
        trace_root,
        n_prompt: audit.n_prompt,
        n_pos: audit.n_pos,
    };
    chain::verify_resid_opening(&rules.ctx, cc, &resp, seed, &op).map_err(|_| "residual point")
}

/// Checks that a recurrent opening body proves the recurrent point of `audit` under `seed`.
fn recur_opening_valid(
    rules: &keryx_consensus_core::config::params::TraceRules,
    audit: &TraceAudit,
    seed: &[u8; 32],
    txid: &[u8; 32],
    body: &[u8],
) -> Result<(), &'static str> {
    use keryx_verifiable_inference::{
        opening::{RecurOpening, inner_body},
        recur, verify,
    };
    let op = inner_body(body)
        .as_deref()
        .and_then(RecurOpening::decode)
        .ok_or("malformed recurrent body")?;
    if &op.response_txid != txid {
        return Err("response id mismatch");
    }
    let cc = rules
        .chain
        .as_ref()
        .ok_or("recurrence without stage-2 rules")?;
    let resp = verify::ResponseCtx {
        trace_root: audit.trace_root,
        n_prompt: audit.n_prompt,
        n_pos: audit.n_pos,
    };
    recur::verify_recur_point(&rules.ctx, cc, &resp, seed, &op).map_err(|_| "recurrent point")
}

/// Checks that an attention opening body proves the phase `audit` awaits of its attention point
/// under `seed`.
fn attn_opening_valid(
    rules: &keryx_consensus_core::config::params::TraceRules,
    audit: &TraceAudit,
    seed: &[u8; 32],
    txid: &[u8; 32],
    body: &[u8],
) -> Result<keryx_verifiable_inference::chain::AttnStep, &'static str> {
    use keryx_verifiable_inference::{
        chain,
        opening::{AttnOpening, inner_body},
        verify,
    };
    let op = inner_body(body)
        .as_deref()
        .and_then(AttnOpening::decode)
        .ok_or("malformed attention body")?;
    if &op.response_txid != txid {
        return Err("response id mismatch");
    }
    let (path, root) = match &audit.attn {
        Some(p) => (&p.path[..], Some(&p.root)),
        None => (&[][..], None),
    };
    let cc = rules
        .chain
        .as_ref()
        .ok_or("attention without stage-2 rules")?;
    let resp = verify::ResponseCtx {
        trace_root: audit.trace_root,
        n_prompt: audit.n_prompt,
        n_pos: audit.n_pos,
    };
    chain::verify_attn_phase(&rules.ctx, cc, &resp, seed, path, root, &op)
        .map_err(|_| "attention point")
}

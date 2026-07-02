//! HTTP API for the sidecar. JSON in/out; addresses + byte fields are hex
//! strings, uint256 fields are decimal strings.

use alloy_primitives::U256;
use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::behavioral::IsolationForest;
use crate::sig_inspect::{self, Eip3009Auth, Eip712Domain, Permit2Auth};

pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/score", post(score))
        .route("/inspect/eip3009", post(inspect_eip3009))
        .route("/inspect/permit2", post(inspect_permit2))
        // Cap request bodies (defense against a /score vector flood).
        .layer(DefaultBodyLimit::max(1024 * 1024))
}

async fn health() -> &'static str {
    "ok"
}

// ─── behavioral scoring ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScoreRequest {
    vectors: Vec<Vec<f64>>,
    point: Vec<f64>,
    #[serde(default = "default_trees")]
    trees: usize,
    #[serde(default = "default_sample")]
    sample_size: usize,
    #[serde(default = "default_seed")]
    seed: u32,
}
fn default_trees() -> usize {
    100
}
fn default_sample() -> usize {
    256
}
fn default_seed() -> u32 {
    1337
}

#[derive(Serialize)]
struct ScoreResponse {
    score: f64,
    anomaly: bool,
}

async fn score(Json(req): Json<ScoreRequest>) -> Json<ScoreResponse> {
    let forest = IsolationForest::fit(&req.vectors, req.trees, req.sample_size, req.seed);
    let score = forest.anomaly_score(&req.point);
    Json(ScoreResponse { score, anomaly: score > 0.7 })
}

// ─── signature inspection ────────────────────────────────────────────────────

type ApiResult<T> = Result<T, (StatusCode, String)>;
fn bad(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

fn parse_fixed<const N: usize>(s: &str) -> ApiResult<[u8; N]> {
    let v = hex::decode(s.trim_start_matches("0x")).map_err(|e| bad(e.to_string()))?;
    if v.len() != N {
        return Err(bad(format!("expected {N} bytes, got {}", v.len())));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}
fn parse_u256(s: &str) -> ApiResult<U256> {
    s.parse::<U256>().map_err(|_| bad(format!("invalid uint256: {s}")))
}
fn hex_addr(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

#[derive(Deserialize)]
struct DomainDto {
    name: String,
    #[serde(default)]
    version: Option<String>,
    chain_id: u64,
    verifying_contract: String,
}

#[derive(Deserialize)]
struct Eip3009Dto {
    from: String,
    to: String,
    value: String,
    valid_after: String,
    valid_before: String,
    nonce: String,
}

#[derive(Deserialize)]
struct InspectEip3009Request {
    domain: DomainDto,
    auth: Eip3009Dto,
    signature: String,
    #[serde(default)]
    now: u64,
}

#[derive(Serialize)]
struct InspectEip3009Response {
    signer: String,
    signer_matches_from: bool,
    recipient: String,
    amount: String,
    expired: bool,
    not_yet_valid: bool,
}

async fn inspect_eip3009(
    Json(req): Json<InspectEip3009Request>,
) -> ApiResult<Json<InspectEip3009Response>> {
    let domain = Eip712Domain {
        name: req.domain.name,
        version: req.domain.version,
        chain_id: req.domain.chain_id,
        verifying_contract: parse_fixed::<20>(&req.domain.verifying_contract)?,
    };
    let auth = Eip3009Auth {
        from: parse_fixed::<20>(&req.auth.from)?,
        to: parse_fixed::<20>(&req.auth.to)?,
        value: parse_u256(&req.auth.value)?,
        valid_after: parse_u256(&req.auth.valid_after)?,
        valid_before: parse_u256(&req.auth.valid_before)?,
        nonce: parse_fixed::<32>(&req.auth.nonce)?,
    };
    let sig = parse_fixed::<65>(&req.signature)?;
    let signer = sig_inspect::recover_eip3009(&domain, &auth, &sig)
        .ok_or_else(|| bad("signature recovery failed"))?;
    let now = U256::from(req.now);

    Ok(Json(InspectEip3009Response {
        signer: hex_addr(&signer),
        signer_matches_from: signer == auth.from,
        recipient: hex_addr(&auth.to),
        amount: auth.value.to_string(),
        expired: req.now != 0 && auth.valid_before < now,
        not_yet_valid: req.now != 0 && auth.valid_after > now,
    }))
}

#[derive(Deserialize)]
struct Permit2Dto {
    token: String,
    amount: String,
    spender: String,
    nonce: String,
    deadline: String,
    witness_to: String,
    witness_valid_after: String,
}

#[derive(Deserialize)]
struct InspectPermit2Request {
    domain: DomainDto,
    auth: Permit2Dto,
    signature: String,
    #[serde(default)]
    now: u64,
}

#[derive(Serialize)]
struct InspectPermit2Response {
    signer: String,
    token: String,
    amount: String,
    recipient: String,
    spender: String,
    expired: bool,
}

async fn inspect_permit2(
    Json(req): Json<InspectPermit2Request>,
) -> ApiResult<Json<InspectPermit2Response>> {
    let domain = Eip712Domain {
        name: req.domain.name,
        version: req.domain.version,
        chain_id: req.domain.chain_id,
        verifying_contract: parse_fixed::<20>(&req.domain.verifying_contract)?,
    };
    let auth = Permit2Auth {
        token: parse_fixed::<20>(&req.auth.token)?,
        amount: parse_u256(&req.auth.amount)?,
        spender: parse_fixed::<20>(&req.auth.spender)?,
        nonce: parse_u256(&req.auth.nonce)?,
        deadline: parse_u256(&req.auth.deadline)?,
        witness_to: parse_fixed::<20>(&req.auth.witness_to)?,
        witness_valid_after: parse_u256(&req.auth.witness_valid_after)?,
    };
    let sig = parse_fixed::<65>(&req.signature)?;
    let signer = sig_inspect::recover_permit2(&domain, &auth, &sig)
        .ok_or_else(|| bad("signature recovery failed"))?;
    let now = U256::from(req.now);

    Ok(Json(InspectPermit2Response {
        signer: hex_addr(&signer),
        token: hex_addr(&auth.token),
        amount: auth.amount.to_string(),
        recipient: hex_addr(&auth.witness_to),
        spender: hex_addr(&auth.spender),
        expired: req.now != 0 && auth.deadline < now,
    }))
}

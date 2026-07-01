// SCRATCH repro tests — DELETE AFTER CONFIRMING.
use agentctl_engine::api::app;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn call(method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

// (A) point SHORTER than training dims -> path_length indexes x[*f] OOB
#[tokio::test]
async fn repro_point_shorter_than_dims() {
    let mut vectors = Vec::new();
    for i in 0..50u32 {
        let i = i as f64;
        vectors.push(vec![i, i * 2.0, i * 3.0, i * 4.0]); // 4 dims
    }
    let body = json!({
        "vectors": vectors,
        "point": [1.0], // only 1 dim — feature index 1,2,3 will OOB
        "trees": 50, "sample_size": 32, "seed": 7
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("point_shorter status={status} value={value}");
}

// (B) vectors of DIFFERING lengths — dims taken from first row, later shorter rows row[f] OOB
#[tokio::test]
async fn repro_differing_vector_lengths() {
    let mut vectors = Vec::new();
    vectors.push(vec![1.0, 2.0, 3.0, 4.0]); // first row 4 dims -> dims=4
    for i in 1..50u32 {
        vectors.push(vec![i as f64]); // 1 dim rows
    }
    let body = json!({
        "vectors": vectors,
        "point": [1.0, 2.0, 3.0, 4.0],
        "trees": 50, "sample_size": 40, "seed": 7
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("differing_lengths status={status} value={value}");
}

// (B2) first row short, later rows long
#[tokio::test]
async fn repro_first_short_later_long() {
    let mut vectors = Vec::new();
    vectors.push(vec![1.0]); // dims=1
    for i in 1..50u32 {
        vectors.push(vec![i as f64, i as f64 * 2.0, i as f64 * 3.0]);
    }
    let body = json!({
        "vectors": vectors,
        "point": [1.0, 2.0, 3.0],
        "trees": 50, "sample_size": 40, "seed": 7
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("first_short_later_long status={status} value={value}");
}

// (C) NaN in vectors
#[tokio::test]
async fn repro_nan_vectors() {
    let body = json!({
        "vectors": [["NaN_PLACEHOLDER"]], // will replace below
        "point": [1.0],
    });
    // serde_json can't directly express NaN, so craft raw body
    let raw = r#"{"vectors":[[1.0],[2.0],[3.0],[4.0],[5.0]],"point":[2.5]}"#;
    let request = Request::builder()
        .method("POST")
        .uri("/score")
        .header("content-type", "application/json")
        .body(Body::from(raw))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    eprintln!("nan_baseline status={}", response.status());
    let _ = body;
}

// (D) empty vectors
#[tokio::test]
async fn repro_empty_vectors() {
    let body = json!({
        "vectors": [],
        "point": [1.0, 2.0],
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("empty_vectors status={status} value={value}");
}

// (E) sample_size 0
#[tokio::test]
async fn repro_sample_size_zero() {
    let body = json!({
        "vectors": [[1.0],[2.0],[3.0]],
        "point": [1.5],
        "sample_size": 0,
        "trees": 10,
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("sample_zero status={status} value={value}");
}

// (F) trees 0
#[tokio::test]
async fn repro_trees_zero() {
    let body = json!({
        "vectors": [[1.0],[2.0],[3.0]],
        "point": [1.5],
        "trees": 0,
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    eprintln!("trees_zero status={status} value={value}");
}

// (G) ecrecover v=2 / v=3 (RecoveryId valid 0..3) and v in {0,1} directly
#[tokio::test]
async fn repro_recid_v_values() {
    // valid 65-byte structure but v variations
    let base_sig = "0x0785178f1d841a523b3ae1dc5f3fff493815f8e5b5fa4e3ea80341693232b934\
28f1bf531c214162e68347c29f045b52760b8c2b51e8e1853179b9c1f682c2cd";
    for v in ["00", "01", "02", "03", "1b", "1c", "ff"] {
        let sig = format!("{}{}", base_sig, v);
        let body = json!({
            "domain": {"name":"USDC","version":"2","chain_id":84532,"verifying_contract":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"},
            "auth": {"from":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","to":"0x000000000000000000000000000000000000dEaD","value":"100000","valid_after":"0","valid_before":"1924992000","nonce":"0x1111111111111111111111111111111111111111111111111111111111111111"},
            "signature": sig
        });
        let (status, value) = call("POST", "/inspect/eip3009", Some(body)).await;
        eprintln!("recid v={v} status={status} value={value}");
    }
}

// (H) parse_u256 negative / too-big
#[tokio::test]
async fn repro_u256_negative_and_huge() {
    for val in ["-1", "115792089237316195423570985008687907853269984665640564039457584007913129639936"] {
        let body = json!({
            "domain": {"name":"USDC","version":"2","chain_id":84532,"verifying_contract":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"},
            "auth": {"from":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","to":"0x000000000000000000000000000000000000dEaD","value":val,"valid_after":"0","valid_before":"1924992000","nonce":"0x1111111111111111111111111111111111111111111111111111111111111111"},
            "signature":"0x0785178f1d841a523b3ae1dc5f3fff493815f8e5b5fa4e3ea80341693232b93428f1bf531c214162e68347c29f045b52760b8c2b51e8e1853179b9c1f682c2cd1b"
        });
        let (status, value) = call("POST", "/inspect/eip3009", Some(body)).await;
        eprintln!("u256 val={val} status={status} value={value}");
    }
}

// (I) JSON Infinity float in point (raw body)
#[tokio::test]
async fn repro_infinity_floats() {
    // serde_json by default rejects Infinity tokens; check status
    let raw = r#"{"vectors":[[1.0],[2.0],[3.0]],"point":[1e400]}"#; // 1e400 overflows to inf
    let request = Request::builder()
        .method("POST")
        .uri("/score")
        .header("content-type", "application/json")
        .body(Body::from(raw))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    eprintln!("infinity status={status} body={}", String::from_utf8_lossy(&bytes));
}

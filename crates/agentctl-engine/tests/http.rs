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

#[tokio::test]
async fn health_returns_ok() {
    let request = Request::builder().uri("/health").body(Body::empty()).unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"ok");
}

#[tokio::test]
async fn score_flags_an_outlier() {
    let mut vectors = Vec::new();
    for i in 0..120u32 {
        let i = i as f64;
        vectors.push(vec![
            80000.0 + (i * 137.0) % 40000.0,
            1.0 + (i * 7.0) % 60.0,
            (i * 5.0) % 24.0,
            if (i as i64) % 6 == 0 { 1.0 } else { 0.0 },
        ]);
    }
    let body = json!({
        "vectors": vectors,
        "point": [50_000_000_000.0, 30.0, 12.0, 1.0],
        "trees": 120, "sample_size": 128, "seed": 42
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["score"].as_f64().unwrap() > 0.6, "got {value}");
}

#[tokio::test]
async fn score_with_mismatched_point_length_does_not_crash() {
    // A point shorter than the training vectors must return 200, not panic (DoS).
    let body = json!({
        "vectors": [[1.0, 2.0, 3.0, 4.0], [5.0, 6.0, 7.0, 8.0]],
        "point": [1.0],
        "trees": 10, "sample_size": 2, "seed": 1
    });
    let (status, value) = call("POST", "/score", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["score"].is_number());
}

#[tokio::test]
async fn inspect_eip3009_recovers_the_signer() {
    let body = json!({
        "domain": {"name":"USDC","version":"2","chain_id":84532,"verifying_contract":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"},
        "auth": {"from":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","to":"0x000000000000000000000000000000000000dEaD","value":"100000","valid_after":"0","valid_before":"1924992000","nonce":"0x1111111111111111111111111111111111111111111111111111111111111111"},
        "signature":"0x0785178f1d841a523b3ae1dc5f3fff493815f8e5b5fa4e3ea80341693232b93428f1bf531c214162e68347c29f045b52760b8c2b51e8e1853179b9c1f682c2cd1b",
        "now": 1700000000
    });
    let (status, value) = call("POST", "/inspect/eip3009", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["signer_matches_from"], json!(true));
    assert_eq!(value["amount"], json!("100000"));
    assert_eq!(value["expired"], json!(false));
    assert_eq!(
        value["recipient"].as_str().unwrap().to_lowercase(),
        "0x000000000000000000000000000000000000dead"
    );
}

#[tokio::test]
async fn inspect_eip3009_rejects_malformed_signature() {
    let body = json!({
        "domain": {"name":"USDC","version":"2","chain_id":84532,"verifying_contract":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"},
        "auth": {"from":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","to":"0x000000000000000000000000000000000000dEaD","value":"100000","valid_after":"0","valid_before":"1924992000","nonce":"0x1111111111111111111111111111111111111111111111111111111111111111"},
        "signature":"0xdead"
    });
    let (status, _) = call("POST", "/inspect/eip3009", Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn inspect_permit2_recovers_the_signer() {
    let body = json!({
        "domain": {"name":"Permit2","chain_id":84532,"verifying_contract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
        "auth": {"token":"0x036CbD53842c5426634e7929541eC2318f3dCF7e","amount":"100000","spender":"0x402085c248EeA27D92E8b30b2C58ed07f9E20001","nonce":"7","deadline":"1924992000","witness_to":"0x000000000000000000000000000000000000dEaD","witness_valid_after":"0"},
        "signature":"0x67ba3ff26b3b1adf897034bef36d0c5c4ba510ba8028411c5ad6d15dae4cf98077b65c1f7274e1daf0222f9d698e18ab8c2f54e0cadd3c779c9c49439bdac16a1c"
    });
    let (status, value) = call("POST", "/inspect/permit2", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value["signer"].as_str().unwrap().to_lowercase(),
        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
    );
    assert_eq!(value["amount"], json!("100000"));
}

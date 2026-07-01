// SCRATCH repro 2 — DELETE AFTER. Real server: does a handler panic kill the
// process or just abort the one connection? Plus NaN + next_f64==1.0 analysis.
use agentctl_engine::api::app;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn http_post(addr: &str, path: &str, body: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    Ok(resp)
}

fn http_get(addr: &str, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    Ok(resp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repro_real_server_panic_isolation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let addr_str = addr.to_string();
    tokio::spawn(async move {
        axum::serve(listener, app()).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Build a panic-inducing /score body (point shorter than dims).
    let mut vectors = Vec::new();
    for i in 0..50u32 {
        let i = i as f64;
        vectors.push(format!("[{i},{},{},{}]", i * 2.0, i * 3.0, i * 4.0));
    }
    let body = format!(
        r#"{{"vectors":[{}],"point":[1.0],"trees":50,"sample_size":32,"seed":7}}"#,
        vectors.join(",")
    );

    let a = addr_str.clone();
    let b = body.clone();
    let r1 = tokio::task::spawn_blocking(move || http_post(&a, "/score", &b))
        .await
        .unwrap();
    eprintln!(
        "ISOLATION: panic /score response = {:?}",
        r1.as_ref().map(|s| s.lines().next().unwrap_or("").to_string())
    );

    tokio::time::sleep(Duration::from_millis(150)).await;

    let a2 = addr_str.clone();
    let r2 = tokio::task::spawn_blocking(move || http_get(&a2, "/health"))
        .await
        .unwrap();
    match r2 {
        Ok(s) => {
            let status_line = s.lines().next().unwrap_or("").to_string();
            let alive = s.contains("200") && s.contains("ok");
            eprintln!("ISOLATION: /health AFTER panic = {status_line:?} -> SERVER {} | full={s:?}",
                if alive { "SURVIVED" } else { "STATE-UNKNOWN" });
        }
        Err(e) => eprintln!("ISOLATION: /health AFTER panic ERRORED = {e} (server may be down)"),
    }
}

// NaN in data: does it panic? what score?
#[tokio::test]
async fn repro_nan_in_data_directly() {
    use agentctl_engine::behavioral::IsolationForest;
    let mut data = Vec::new();
    for i in 0..100 {
        data.push(vec![i as f64, (i % 7) as f64]);
    }
    data.push(vec![f64::NAN, f64::NAN]);
    let forest = IsolationForest::fit(&data, 50, 64, 7);
    let s_nan = forest.anomaly_score(&[f64::NAN, f64::NAN]);
    let s_norm = forest.anomaly_score(&[50.0, 3.0]);
    eprintln!("NaN score={s_nan} (finite={}), normal score={s_norm}", s_nan.is_finite());
}

// Brute-force max of mulberry32 next_f64 — can it hit exactly 1.0?
#[tokio::test]
async fn repro_next_f64_range() {
    fn mulberry(state: &mut u32) -> f64 {
        *state = state.wrapping_add(0x6d2b_79f5);
        let mut t = (*state ^ (*state >> 15)).wrapping_mul(1 | *state);
        t = (t.wrapping_add((t ^ (t >> 7)).wrapping_mul(61 | t))) ^ t;
        ((t ^ (t >> 14)) as f64) / 4_294_967_296.0
    }
    let mut max = 0.0f64;
    let mut hit_one = false;
    let mut s: u32 = 0;
    for _ in 0..50_000_000u64 {
        let x = mulberry(&mut s);
        if x > max { max = x; }
        if x >= 1.0 { hit_one = true; }
    }
    eprintln!("next_f64 max over 50M steps = {max:.12}, hit>=1.0 = {hit_one}");
}

#![allow(clippy::field_reassign_with_default)]
//! Compatibility regression tests ensuring Hide-Go never breaks supported AI coding harnesses.

use axum::{
    body::Bytes,
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Router,
};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use hide_core::all_hide::AllHideEngine;
use hide_core::ca::{CaManager, MockCaTrustAdapter};
use hide_core::connect::build_gateway_service;
use hide_core::desensitizer::SemanticDesensitizer;
use hide_core::sse_restorer::SseRestorer;
use hide_core::vault::PrivacyVault;
use hide_core::{build_router, GatewayState, HideConfig, PrivacyMode, ToolCallSecretPolicy, TrafficCategory};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

async fn serve_gateway(state: GatewayState) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = state.get_config();
    cfg.proxy_port = addr.port();
    let _ = state.try_update_config(cfg);
    let svc = build_gateway_service(state, None);
    tokio::spawn(async move {
        let _ = axum::serve(listener, svc).await;
    });
    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn c01_gzip_and_deflate_requests_are_decompressed_desensitized_and_forwarded() {
    let seen = Arc::new(Mutex::new(Vec::<(Option<String>, String)>::new()));
    let seen_ref = seen.clone();
    let upstream = serve(Router::new().fallback(move |headers: HeaderMap, body: Bytes| {
        let seen_ref = seen_ref.clone();
        async move {
            let ce = headers
                .get(header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let text = String::from_utf8_lossy(&body).to_string();
            seen_ref.lock().unwrap().push((ce, text.clone()));
            let parsed: Value = serde_json::from_str(&text).expect("upstream must receive valid JSON");
            let prompt = parsed["messages"][0]["content"].as_str().unwrap_or("");
            axum::Json(json!({
                "id": "msg_1",
                "type": "message",
                "content": [{"type": "text", "text": prompt}]
            }))
        }
    }))
    .await;

    let state =
        GatewayState::with_admin_token(HideConfig::default(), "compat-token-0123456789").with_loopback_for_tests(true);
    let gw = serve(build_router(state.clone())).await;

    let real_key = "sk-ant-api03-CompatGzipSecret9876543210";
    let raw_json = json!({
        "model": "claude-sonnet-4-5",
        "messages": [{"role": "user", "content": format!("use {real_key}")}]
    })
    .to_string();

    // 1. Gzip request body
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(raw_json.as_bytes()).unwrap();
    let gzip_bytes = gz.finish().unwrap();

    let gz_resp = client()
        .post(format!("{gw}/claude-code/v1/messages"))
        .header("x-hide-go-token", state.admin_token())
        .header("x-hide-go-upstream", &upstream)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(gzip_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(gz_resp.status(), StatusCode::OK);
    let gz_out: Value = gz_resp.json().await.unwrap();
    assert_eq!(gz_out["content"][0]["text"], format!("use {real_key}"));

    // 2. Deflate (zlib-wrapped) request body
    let mut def = ZlibEncoder::new(Vec::new(), Compression::default());
    def.write_all(raw_json.as_bytes()).unwrap();
    let deflate_bytes = def.finish().unwrap();

    let def_resp = client()
        .post(format!("{gw}/claude-code/v1/messages"))
        .header("x-hide-go-token", state.admin_token())
        .header("x-hide-go-upstream", &upstream)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_ENCODING, "deflate")
        .body(deflate_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(def_resp.status(), StatusCode::OK);
    let def_out: Value = def_resp.json().await.unwrap();
    assert_eq!(def_out["content"][0]["text"], format!("use {real_key}"));

    // Upstream never received the real key and never received a stale Content-Encoding header.
    {
        let captured = seen.lock().unwrap();
        assert_eq!(captured.len(), 2);
        for (ce, body_str) in captured.iter() {
            assert!(
                ce.is_none(),
                "Content-Encoding must be stripped after decompression: {ce:?}"
            );
            assert!(!body_str.contains("CompatGzipSecret9876543210"), "{body_str}");
        }
    }

    // 3. Corrupt gzip bytes still fail closed with 415.
    let bad_resp = client()
        .post(format!("{gw}/claude-code/v1/messages"))
        .header("x-hide-go-token", state.admin_token())
        .header("x-hide-go-upstream", &upstream)
        .header(header::CONTENT_ENCODING, "gzip")
        .body(vec![0x1f, 0x8b, 0x08, 0x00, 0xff])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn c02_multipart_form_data_passes_through_without_415() {
    let seen = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let seen_ref = seen.clone();
    let upstream = serve(Router::new().fallback(move |body: Bytes| {
        let seen_ref = seen_ref.clone();
        async move {
            seen_ref.lock().unwrap().push(body.to_vec());
            axum::Json(json!({"text": "transcribed"}))
        }
    }))
    .await;

    let state =
        GatewayState::with_admin_token(HideConfig::default(), "compat-token-0123456789").with_loopback_for_tests(true);
    let gw = serve(build_router(state.clone())).await;

    let mut multipart_bytes = Vec::new();
    multipart_bytes.extend_from_slice(b"-----test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"img.png\"\r\nContent-Type: image/png\r\n\r\n");
    multipart_bytes.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe]);
    multipart_bytes.extend_from_slice(b"\r\n-----test--\r\n");

    let resp = client()
        .post(format!("{gw}/codex/v1/audio/transcriptions"))
        .header("x-hide-go-token", state.admin_token())
        .header("x-hide-go-upstream", &upstream)
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=---test")
        .body(multipart_bytes.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.json::<Value>().await.unwrap()["text"], "transcribed");
    let captured = seen.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], multipart_bytes);
}

#[tokio::test]
async fn c03_compressed_upstream_gzip_response_is_transparently_decompressed_and_restored() {
    let upstream = serve(Router::new().fallback(|body: Bytes| async move {
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let prompt = parsed["messages"][0]["content"].as_str().unwrap_or("");
        let json_resp = json!({
            "id": "msg_gz",
            "content": [{"type": "text", "text": prompt}]
        })
        .to_string();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(json_resp.as_bytes()).unwrap();
        let compressed = gz.finish().unwrap();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .body(axum::body::Body::from(compressed))
            .unwrap()
    }))
    .await;

    let state =
        GatewayState::with_admin_token(HideConfig::default(), "compat-token-0123456789").with_loopback_for_tests(true);
    let gw = serve(build_router(state.clone())).await;

    let real_key = "sk-ant-api03-UpstreamGzipSecret55555555";
    let resp = client()
        .post(format!("{gw}/claude-code/v1/messages"))
        .header("x-hide-go-token", state.admin_token())
        .header("x-hide-go-upstream", &upstream)
        .json(&json!({
            "model": "claude-sonnet-4-5",
            "messages": [{"role": "user", "content": format!("echo {real_key}")}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let out: Value = resp.json().await.unwrap();
    assert_eq!(out["content"][0]["text"], format!("echo {real_key}"));
}

#[tokio::test]
async fn c04_mitm_supports_http2_and_preserves_cors_and_non_session_cookies() {
    let gateway_ca = Arc::new(CaManager::ephemeral(Arc::new(MockCaTrustAdapter::new())).unwrap());
    let upstream_ca = Arc::new(CaManager::ephemeral(Arc::new(MockCaTrustAdapter::new())).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_proxy_addr = listener.local_addr().unwrap();
    let upstream_ca_ref = upstream_ca.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let upstream_ca = upstream_ca_ref.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let target = req_line.split_whitespace().nth(1).unwrap_or("");
                let host = target.split(':').next().unwrap_or(target).to_string();
                let mut stream = reader.into_inner();
                if stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(server_cfg) = upstream_ca.server_config_for_host_async(&host).await else {
                    return;
                };
                let Ok(tls_stream) = TlsAcceptor::from(server_cfg).accept(stream).await else {
                    return;
                };
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| async move {
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
                    assert!(!body_str.contains("Http2MitmSecret998877"));
                    let parsed: Value = serde_json::from_str(&body_str).unwrap();
                    let content = parsed["messages"][0]["content"].as_str().unwrap_or("");
                    let resp_json = json!({
                        "id": "chat_h2",
                        "choices": [{"message": {"role": "assistant", "content": content}}]
                    })
                    .to_string();
                    let resp = hyper::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .header("access-control-allow-origin", "https://vscode.dev")
                        .header("set-cookie", "__cf_bm=ok; Path=/")
                        .header("set-cookie", "hide_go_session=evil")
                        .body(Full::new(Bytes::from(resp_json)))
                        .unwrap();
                    Ok::<_, Infallible>(resp)
                });
                let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), svc)
                    .await;
            });
        }
    });

    let mut state = GatewayState::new(HideConfig::default()).with_ca(gateway_ca.clone());
    state.http_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(upstream_ca.ca_cert_pem().as_bytes()).unwrap())
        .proxy(reqwest::Proxy::all(format!("http://{mock_proxy_addr}")).unwrap())
        .build()
        .unwrap();
    let gw_addr = serve_gateway(state).await;

    let proxy_client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{gw_addr}")).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(gateway_ca.ca_cert_pem().as_bytes()).unwrap())
        .build()
        .unwrap();

    let real_secret = "sk-ant-api03-Http2MitmSecret9988776655";
    let resp = proxy_client
        .post("https://api.openai.com/v1/chat/completions")
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": format!("test {real_secret}")}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://vscode.dev")
    );
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    assert!(cookies.iter().any(|c| c == "__cf_bm=ok; Path=/"), "{cookies:?}");
    assert!(!cookies.iter().any(|c| c.contains("hide_go_session")), "{cookies:?}");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], format!("test {real_secret}"));
}

#[test]
fn c05_sse_restorer_handles_single_newline_done_and_max_tokens_truncated_tool_json() {
    // 1. Single-newline terminated `data: [DONE]\n` at EOF
    let vault = PrivacyVault::new();
    vault.insert_explicit("real_val", "MASK_VAL", "test");
    let mut r1 = SseRestorer::new(vault.clone());
    let sse_single_nl = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"MASK_VAL\"}}]}\n\n",
        "data: [DONE]\n"
    );
    let mut out1 = r1.push_bytes(sse_single_nl.as_bytes()).unwrap();
    let (tail1, count1) = r1.finish().unwrap();
    out1.push_str(&tail1);
    assert!(out1.contains("real_val"), "{out1}");
    assert!(out1.contains("data: [DONE]"), "{out1}");
    assert_eq!(count1, 1);

    // 2. Anthropic max_tokens truncation inside tool_use partial_json
    let vault2 = PrivacyVault::new();
    vault2.insert_explicit("/home/alice", "/workspace/user_01", "ProjectPath");
    vault2.insert_explicit("sk-ant-real-secret-999", "sk-sem-placeholder-key-0001", "ApiKey");
    let mut r2 = SseRestorer::with_policy(vault2, ToolCallSecretPolicy::FileEditsOnly);
    let mut stream2 = String::new();
    stream2.push_str(&format!(
        "event: content_block_start\ndata: {}\n\n",
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tu_1", "name": "Write", "input": {}}})
    ));
    stream2.push_str(&format!(
        "event: content_block_delta\ndata: {}\n\n",
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"file_path\":\"/workspace/user_01/a.rs\",\"content\":\"sk-sem-placeholder-key-0001"}})
    ));
    stream2.push_str(&format!(
        "event: message_delta\ndata: {}\n\n",
        json!({"type": "message_delta", "delta": {"stop_reason": "max_tokens"}})
    ));
    stream2.push_str(&format!(
        "event: content_block_stop\ndata: {}\n\n",
        json!({"type": "content_block_stop", "index": 0})
    ));
    stream2.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");

    let mut out2 = r2.push_bytes(stream2.as_bytes()).unwrap();
    out2.push_str(&r2.finish().unwrap().0);
    assert!(out2.contains("/home/alice/a.rs"), "{out2}");
    assert!(out2.contains("sk-ant-real-secret-999"), "{out2}");
    assert!(out2.contains("max_tokens"), "{out2}");

    // 3. OpenAI Responses `response.reasoning_summary_text.delta` split across chunks
    let mut r3 = SseRestorer::new(vault);
    let d1 = format!(
        "data: {}\n\n",
        json!({"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "output_index": 0, "delta": "see MASK_"})
    );
    let d2 = format!(
        "data: {}\n\n",
        json!({"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "output_index": 0, "delta": "VAL here"})
    );
    let done = format!(
        "data: {}\n\n",
        json!({"type": "response.reasoning_summary_text.done", "item_id": "rs_1", "output_index": 0})
    );
    let mut out3 = String::new();
    out3.push_str(&r3.push_bytes(d1.as_bytes()).unwrap());
    out3.push_str(&r3.push_bytes(d2.as_bytes()).unwrap());
    out3.push_str(&r3.push_bytes(done.as_bytes()).unwrap());
    out3.push_str(&r3.finish().unwrap().0);
    assert!(out3.contains("real_val"), "{out3}");
    assert!(!out3.contains("MASK_VAL"), "{out3}");
}

#[test]
fn c06_gemini_thought_signature_and_json_boolean_short_token_preserved() {
    let fake_sig = "sk-ant-api03-fake1234567890abcdef";
    let payload = json!({
        "contents": [{
            "role": "model",
            "parts": [{
                "text": "I don't think it's broken; const s = 'confidential_value'; fn svc_payment_router() {}",
                "thoughtSignature": fake_sig,
                "thought_signature": fake_sig
            }]
        }],
        "config": {
            "secret": false,
            "password": true,
            "token": "fn",
            "api_key": "real-api-key-value-999"
        }
    })
    .to_string();

    // AutoDesensitize
    let cfg = HideConfig::default();
    let vault = PrivacyVault::new();
    let res = SemanticDesensitizer::process(&payload, &cfg, &vault);
    let parsed: Value = serde_json::from_str(&res.transformed_payload).unwrap();
    assert_eq!(parsed["contents"][0]["parts"][0]["thoughtSignature"], fake_sig);
    assert_eq!(parsed["contents"][0]["parts"][0]["thought_signature"], fake_sig);
    assert_eq!(parsed["config"]["secret"], json!(false));
    assert_eq!(parsed["config"]["password"], json!(true));
    assert_eq!(parsed["config"]["token"], json!("fn"));
    assert_ne!(parsed["config"]["api_key"], json!("real-api-key-value-999"));

    // AllHide
    let mut ah_cfg = HideConfig::default();
    ah_cfg.mode = PrivacyMode::AllHide;
    ah_cfg.all_hide.strict_literal_masking = true;
    ah_cfg.all_hide.enable_isomorphic_camouflage = true;
    ah_cfg.all_hide.enable_cipher_garble = false;
    let ah_vault = PrivacyVault::new();
    let ah_out = AllHideEngine::process(&payload, TrafficCategory::InteractivePrompt, &ah_cfg, &ah_vault);
    let ah_parsed: Value = serde_json::from_str(&ah_out.vendor_payload).unwrap();
    assert_eq!(ah_parsed["contents"][0]["parts"][0]["thoughtSignature"], fake_sig);
    assert_eq!(ah_parsed["contents"][0]["parts"][0]["thought_signature"], fake_sig);

    let text = ah_parsed["contents"][0]["parts"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("I don't think it's broken"),
        "contraction was masked: {text}"
    );
    assert!(
        !text.contains("confidential_value"),
        "quoted literal not masked: {text}"
    );
    assert!(
        !text.contains("svc_payment_router"),
        "svc_payment_router was skipped: {text}"
    );

    // Own `svc-node-...` token is still preserved as an own token
    let own = "connect to svc-node-deadbeef-01";
    let own_out = AllHideEngine::process(own, TrafficCategory::InteractivePrompt, &ah_cfg, &ah_vault);
    assert!(
        own_out.vendor_payload.contains("svc-node-deadbeef-01"),
        "{}",
        own_out.vendor_payload
    );
}

#[test]
fn c07_vault_scoped_matcher_is_cached_and_invalidates_on_insert() {
    let vault = PrivacyVault::new();
    vault.get_or_insert_scoped_with(Some("harness:cursor"), "secret_one", "ApiKey", |_| {
        "sk-sem-one-0001".to_string()
    });
    let m1 = vault.matcher_for_scope(Some("harness:cursor"));
    let m2 = vault.matcher_for_scope(Some("harness:cursor"));
    assert!(
        Arc::ptr_eq(&m1, &m2),
        "scoped matcher should reuse cached Arc when generation unchanged"
    );

    vault.get_or_insert_scoped_with(Some("harness:cursor"), "secret_two", "ApiKey", |_| {
        "sk-sem-two-0002".to_string()
    });
    let m3 = vault.matcher_for_scope(Some("harness:cursor"));
    assert!(
        !Arc::ptr_eq(&m1, &m3),
        "scoped matcher cache must invalidate after vault write"
    );
}

#[tokio::test]
async fn c08_operator_private_lan_upstream_allowed_while_metadata_and_self_loop_blocked() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_ref = hits.clone();
    let upstream = serve(Router::new().fallback(move |_body: Bytes| {
        let hits_ref = hits_ref.clone();
        async move {
            hits_ref.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({"id": "local_op", "content": [{"type": "text", "text": "ok"}]}))
        }
    }))
    .await;

    // Production-like GatewayState (`allow_loopback_for_tests == false`), configured via harness_upstreams.
    let mut cfg = HideConfig::default();
    cfg.harness_upstreams.insert("claude-code".to_string(), upstream);
    let state = GatewayState::new(cfg);
    let gw_addr = serve_gateway(state.clone()).await;
    let gw = format!("http://{gw_addr}");

    let ok_resp = client()
        .post(format!("{gw}/claude-code/v1/messages"))
        .json(&json!({"model": "claude", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Cloud metadata and self-port in harness_upstreams remain strictly blocked (403).
    for blocked in [
        "http://169.254.169.254",
        &format!("http://127.0.0.1:{}", gw_addr.port()),
    ] {
        let mut bad_cfg = state.get_config();
        bad_cfg
            .harness_upstreams
            .insert("claude-code".to_string(), blocked.to_string());
        state.try_update_config(bad_cfg).unwrap();

        let resp = client()
            .post(format!("{gw}/claude-code/v1/messages"))
            .json(&json!({"model": "claude", "messages": [{"role": "user", "content": "hi"}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "expected 403 for {blocked}");
    }
}

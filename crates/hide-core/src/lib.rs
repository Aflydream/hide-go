#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

pub mod all_hide;
pub mod audit;
pub mod ca;
pub mod config;
pub mod connect;
pub mod desensitizer;
pub mod harness;
pub mod harness_detect;
pub mod ndjson_restorer;
pub mod protobuf;
pub mod protocol;
pub mod proxy;
pub mod restore;
pub mod scanner;
pub mod sse_restorer;
pub mod stream_restorer;
pub mod system_proxy;
pub mod upstream_proxy;
pub mod vault;

pub use ca::{CaManager, CaStatus, CaTrustAdapter, MockCaTrustAdapter, RealCaTrustAdapter};
pub use config::*;
pub use connect::{
    build_gateway_proxy_service, build_gateway_service, should_mitm_host, GatewayMakeService, GatewayProxyService,
};
pub use proxy::{build_router, GatewayState, MIN_ADMIN_TOKEN_LEN};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::all_hide::AllHideEngine;
    use crate::desensitizer::SemanticDesensitizer;
    use crate::harness::{detect_harness_and_category, get_all_harness_profiles};
    use crate::stream_restorer::StreamRestorer;
    use crate::vault::PrivacyVault;

    #[test]
    fn test_all_seven_harnesses_supported_and_detected() {
        let profiles = get_all_harness_profiles(18787);
        assert_eq!(profiles.len(), 7);

        let expected = [
            HarnessKind::ClaudeCode,
            HarnessKind::Codex,
            HarnessKind::Antigravity,
            HarnessKind::Zcode,
            HarnessKind::Qoder,
            HarnessKind::Cursor,
            HarnessKind::GrokBuild,
        ];
        for kind in expected {
            assert!(
                profiles.iter().any(|p| p.kind == kind),
                "Missing profile for {:?}",
                kind
            );
        }

        let (h1, c1) = detect_harness_and_category(
            "/claude-code/api/event_logging",
            Some("claude-code/1.0"),
            r#"{"event":"telemetry"}"#,
        );
        assert_eq!(h1, HarnessKind::ClaudeCode);
        assert_eq!(c1, TrafficCategory::Telemetry);

        let (h2, c2) = detect_harness_and_category(
            "/qoder/v1/codebase/index",
            Some("qoder-agent"),
            r#"{"embeddings": true}"#,
        );
        assert_eq!(h2, HarnessKind::Qoder);
        assert_eq!(c2, TrafficCategory::CodebaseIndexing);

        let (h3, _) = detect_harness_and_category(
            "/grok-build/v1/chat/completions",
            Some("grok-build-cli"),
            r#"{"messages":[]}"#,
        );
        assert_eq!(h3, HarnessKind::GrokBuild);
    }

    #[test]
    fn test_auto_desensitize_and_streaming_restoration() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();

        let original_prompt = r#"
Connect to postgres://prod_admin:MyTopSecret99@10.20.30.40:5432/core_ledger
using API key sk-ant-api03-1234567890abcdef1234567890 in /home/alice/ProjectTitan/src/pay.rs
"#;

        let res = SemanticDesensitizer::process(original_prompt, &cfg, &vault);

        // Vendor must NOT see real secrets, DB credentials, internal IP, or project path
        assert!(!res.transformed_payload.contains("MyTopSecret99"));
        assert!(!res.transformed_payload.contains("10.20.30.40"));
        assert!(!res
            .transformed_payload
            .contains("sk-ant-api03-1234567890abcdef1234567890"));
        assert!(!res.transformed_payload.contains("/home/alice/ProjectTitan/src/pay.rs"));
        assert!(!res.findings.is_empty());

        // Now simulate the LLM streaming back the transformed payload in tiny 4-byte fragments
        let mut restorer = StreamRestorer::new(vault);
        let mut reconstructed = String::new();
        let chars: Vec<char> = res.transformed_payload.chars().collect();
        for chunk in chars.chunks(4) {
            let s: String = chunk.iter().collect();
            reconstructed.push_str(&restorer.push_chunk(&s));
        }
        let (tail, count) = restorer.finish();
        reconstructed.push_str(&tail);

        assert!(count >= 3);
        assert_eq!(reconstructed, original_prompt);
    }

    #[test]
    fn test_all_hide_isomorphic_camouflage_and_restoration() {
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AllHide;
        cfg.all_hide.enable_isomorphic_camouflage = true;
        cfg.all_hide.enable_cipher_garble = false;
        cfg.all_hide.cover_theme = CoverTheme::BotanicalGarden;

        let vault = PrivacyVault::new();
        let secret_code = r#"
// Execute quantum margin settlement
pub fn verify_margin_liquidation(wallet_signature: &str) -> bool {
    calculate_settlement_fee(wallet_signature)
}
"#;

        let out = AllHideEngine::process(secret_code, TrafficCategory::InteractivePrompt, &cfg, &vault);

        // Vendor sees botanical garden identifiers instead of financial settlement identifiers
        assert!(!out.vendor_payload.contains("verify_margin_liquidation"));
        assert!(!out.vendor_payload.contains("wallet_signature"));
        assert!(!out.vendor_payload.contains("calculate_settlement_fee"));
        assert!(!out.vendor_payload.contains("quantum margin"));
        assert!(!out.vendor_payload.contains("BotanicalSensor"));
        assert!(out.vendor_payload.contains("// "));

        // Local restoration recovers the exact original financial code
        let (restored, count) = vault.restore_text(&out.vendor_payload);
        assert!(count >= 3);
        assert_eq!(restored, secret_code);
    }

    #[test]
    fn test_all_hide_cipher_garble_and_chaff() {
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AllHide;
        cfg.all_hide.enable_isomorphic_camouflage = false;
        cfg.all_hide.enable_cipher_garble = true;
        cfg.all_hide.enable_telemetry_chaff = true;

        let vault = PrivacyVault::new();
        let secret_text = "Confidential algorithm in /Users/dev/AflyCore/engine.rs";

        let cipher_out = AllHideEngine::process(secret_text, TrafficCategory::InteractivePrompt, &cfg, &vault);
        assert!(cipher_out.vendor_payload.starts_with("⟦HIDE-CIPHER::"));
        assert!(!cipher_out.vendor_payload.contains("Confidential"));

        let decoded =
            AllHideEngine::decode_braille_cipher_blocks(&cipher_out.vendor_payload, &vault, &cfg.project_salt);
        let (fully_restored, _) = vault.restore_text(&decoded);
        assert_eq!(fully_restored, secret_text);

        // Telemetry request gets replaced with Chaff
        let chaff_out = AllHideEngine::process(secret_text, TrafficCategory::Telemetry, &cfg, &vault);
        assert_eq!(chaff_out.action_taken, "chaff-injected");
        assert!(!chaff_out.vendor_payload.contains("AflyCore"));
    }

    #[test]
    fn test_audit_3_full_pem_private_key_block_masking() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let pem_payload = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA99887766554433221100aabbccddeeff\nSuperSecretPrivateKeyBodyLine2==\n-----END RSA PRIVATE KEY-----\nEnd.";

        let res = SemanticDesensitizer::process(pem_payload, &cfg, &vault);
        assert!(!res.transformed_payload.contains("BEGIN RSA PRIVATE KEY"));
        assert!(!res
            .transformed_payload
            .contains("MIIEpAIBAAKCAQEA99887766554433221100aabbccddeeff"));
        assert!(!res.transformed_payload.contains("SuperSecretPrivateKeyBodyLine2=="));
        assert!(!res.transformed_payload.contains("END RSA PRIVATE KEY"));

        let (restored, count) = vault.restore_text(&res.transformed_payload);
        assert_eq!(count, 1);
        assert_eq!(restored, pem_payload);
    }

    #[test]
    fn test_audit_4_json_desensitization_escaped_windows_path_password_and_quoted_db_url() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();

        let json_payload = r#"{"PASSWORD":"s3cr3t","win_path":"C:\\Users\\alice\\ProjectTitan\\src\\main.rs","escaped_key":"\u0073k-ant-api03-1234567890abcdef1234567890","db_quoted":"postgres://admin:pass\"word@10.10.20.30:5432/prod_db","prompt":"Connect to \"postgres://user:topsecret@192.168.1.50:5432/app\" now"}"#;

        let res = SemanticDesensitizer::process(json_payload, &cfg, &vault);

        // Must be 100% valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&res.transformed_payload).expect("output must be valid JSON");

        // None of the sensitive values may remain in the transformed JSON
        assert!(!res.transformed_payload.contains("s3cr3t"));
        assert!(!res.transformed_payload.contains("Users"));
        assert!(!res.transformed_payload.contains("alice"));
        assert!(!res.transformed_payload.contains("1234567890abcdef1234567890"));
        assert!(!res.transformed_payload.contains("pass\\\"word"));
        assert!(!res.transformed_payload.contains("topsecret"));
        assert!(parsed.get("PASSWORD").is_some());

        // Restoring the transformed JSON must yield valid JSON matching all original fields
        let (restored_json, _) = vault.restore_text(&res.transformed_payload);
        let restored_val: serde_json::Value =
            serde_json::from_str(&restored_json).expect("restored output must be valid JSON");
        let orig_val: serde_json::Value = serde_json::from_str(json_payload).unwrap();
        assert_eq!(restored_val["PASSWORD"], orig_val["PASSWORD"]);
        assert_eq!(restored_val["win_path"], orig_val["win_path"]);
        assert_eq!(restored_val["db_quoted"], orig_val["db_quoted"]);
        assert_eq!(restored_val["prompt"], orig_val["prompt"]);
    }

    #[test]
    fn test_audit_5_strict_literal_masking_and_keyed_cipher_protection() {
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AllHide;
        cfg.all_hide.strict_literal_masking = true;
        cfg.all_hide.enable_isomorphic_camouflage = true;
        cfg.all_hide.enable_cipher_garble = false;

        let vault = PrivacyVault::new();
        let confidential = r#"let msg = "中文机密字面量：核心量子清算密钥阈值";"#;

        let out_iso = AllHideEngine::process(confidential, TrafficCategory::InteractivePrompt, &cfg, &vault);
        assert!(!out_iso.vendor_payload.contains("中文机密字面量"));
        assert!(!out_iso.vendor_payload.contains("核心量子清算"));

        let (restored_iso, _) = vault.restore_text(&out_iso.vendor_payload);
        assert_eq!(restored_iso, confidential);

        // Now test with cipher garble enabled (default All-Hide):
        // Verify that an attacker with an empty/different Vault cannot decode the Chinese literal
        cfg.all_hide.enable_cipher_garble = true;
        let vault2 = PrivacyVault::new();
        let out_cipher = AllHideEngine::process(confidential, TrafficCategory::InteractivePrompt, &cfg, &vault2);
        let attacker_vault = PrivacyVault::new();
        let attacker_attempt =
            AllHideEngine::decode_braille_cipher_blocks(&out_cipher.vendor_payload, &attacker_vault, "wrong-salt");
        assert!(!attacker_attempt.contains("中文机密字面量"));

        // Even with the right salt but without the originating Vault, it cannot be recovered
        let attacker_same_salt =
            AllHideEngine::decode_braille_cipher_blocks(&out_cipher.vendor_payload, &attacker_vault, &cfg.project_salt);
        assert!(!attacker_same_salt.contains("中文机密字面量"));

        // Legitimate owner with `vault2` restores 100% accurately
        let (owner_restored, _) = vault2.restore_text(&out_cipher.vendor_payload);
        assert_eq!(owner_restored, confidential);
    }

    #[test]
    fn test_audit_6_vault_collision_prevention_comments_and_symbols() {
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AllHide;
        cfg.all_hide.enable_isomorphic_camouflage = true;
        cfg.all_hide.enable_cipher_garble = false;
        cfg.all_hide.strict_literal_masking = false;

        let vault = PrivacyVault::new();

        let out1 = AllHideEngine::process(
            "// alpha\npub fn run_alpha_task() {}",
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
        );
        let out2 = AllHideEngine::process(
            "// bravo\npub fn run_bravo_task() {}",
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
        );

        let (restored1, _) = vault.restore_text(&out1.vendor_payload);
        let (restored2, _) = vault.restore_text(&out2.vendor_payload);

        assert_eq!(restored1, "// alpha\npub fn run_alpha_task() {}");
        assert_eq!(restored2, "// bravo\npub fn run_bravo_task() {}");

        // Also test explicit symbol collision in PrivacyVault
        let tok_a = vault.insert_explicit("business_symbol_one", "fern_moss_100", "IsomorphicSymbol");
        let tok_b = vault.insert_explicit("business_symbol_two", "fern_moss_100", "IsomorphicSymbol");
        assert_ne!(tok_a, tok_b);
        assert_eq!(vault.restore_text(&tok_a).0, "business_symbol_one");
        assert_eq!(vault.restore_text(&tok_b).0, "business_symbol_two");
    }

    #[test]
    fn test_audit_8_stream_restorer_prefix_token_chunk_boundary() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("10.0.0.10", "10.254.100.1", "InternalIp");
        vault.insert_explicit("10.0.0.19", "10.254.100.19", "InternalIp");

        let mut restorer = StreamRestorer::new(vault);
        let mut out = String::new();
        // Split right between `10.254.100.1` and `9`
        out.push_str(&restorer.push_chunk("Server is at 10.254.100.1"));
        out.push_str(&restorer.push_chunk("9:8080 and 10.254.100.1 "));
        let (tail, _) = restorer.finish();
        out.push_str(&tail);

        assert_eq!(out, "Server is at 10.0.0.19:8080 and 10.0.0.10 ");
    }

    #[tokio::test]
    async fn test_audit_1_and_2_real_upstream_proxy_streaming_and_admin_auth() {
        use axum::{
            body::Bytes,
            http::{HeaderMap, StatusCode},
            routing::post,
            Router,
        };
        use tokio::net::TcpListener;

        // 1. Start a real mock upstream server that verifies outbound desensitization
        //    and supports both JSON and `stream: true` SSE responses.
        let mock_upstream = Router::new().route(
            "/v1/messages",
            post(|headers: HeaderMap, body: String| async move {
                // Verify secret was desensitized BEFORE reaching upstream!
                assert!(!body.contains("sk-ant-api03-real-secret-key-9999999999"));
                let parsed: serde_json::Value =
                    serde_json::from_str(&body).expect("upstream must receive valid JSON");
                let prompt_text = parsed["messages"][0]["content"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();

                let is_stream = parsed.get("stream").and_then(|v| v.as_bool()) == Some(true)
                    || headers
                        .get("accept")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.contains("text/event-stream"))
                        .unwrap_or(false);

                if is_stream {
                    let full_sse = format!(
                        "data: {{\"id\":\"msg_stream_01\",\"choices\":[{{\"delta\":{{\"content\":{:?}}}}}]}}\n\ndata: [DONE]\n\n",
                        prompt_text
                    );
                    // Split the SSE stream across two network chunks right in the middle of the placeholder token!
                    let split_pos = full_sse.find("placeholder").unwrap_or(full_sse.len() / 2);
                    let chunk1 = full_sse[..split_pos].to_string();
                    let chunk2 = full_sse[split_pos..].to_string();
                    let stream = futures_util::stream::iter(vec![
                        Ok::<Bytes, std::io::Error>(Bytes::from(chunk1)),
                        Ok::<Bytes, std::io::Error>(Bytes::from(chunk2)),
                    ]);
                    axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(stream))
                        .unwrap()
                } else {
                    let resp_json = serde_json::json!({
                        "id": "upstream_real_msg",
                        "echo": prompt_text
                    });
                    axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(resp_json.to_string()))
                        .unwrap()
                }
            }),
        );

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(upstream_listener, mock_upstream).await.unwrap();
        });

        // 2. Start Hide-Go gateway
        let state = GatewayState::with_admin_token(HideConfig::default(), "test-admin-secret-123")
            .with_loopback_for_tests(true);
        let app = build_router(state);
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gateway_listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        // 3. Verify Audit #2: Unauthenticated /api/vault and cross-origin requests are rejected
        let unauth_res = client
            .get(format!("http://{}/api/vault", gateway_addr))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

        let cross_origin_res = client
            .get(format!("http://{}/api/vault", gateway_addr))
            .header("X-Hide-Go-Token", "test-admin-secret-123")
            .header("Origin", "https://evil.attacker.example")
            .send()
            .await
            .unwrap();
        assert_eq!(cross_origin_res.status(), StatusCode::FORBIDDEN);

        let auth_res = client
            .get(format!("http://{}/api/vault", gateway_addr))
            .header("X-Hide-Go-Token", "test-admin-secret-123")
            .send()
            .await
            .unwrap();
        assert_eq!(auth_res.status(), StatusCode::OK);

        // 4. Verify Audit #1: Real upstream forwarding (non-streaming JSON)
        let req_body = serde_json::json!({
            "model": "claude-3-7-sonnet",
            "stream": false,
            "messages": [
                {
                    "role": "user",
                    "content": "Use key sk-ant-api03-real-secret-key-9999999999"
                }
            ]
        });
        let proxy_res = client
            .post(format!("http://{}/claude-code/v1/messages", gateway_addr))
            .header("X-Hide-Go-Token", "test-admin-secret-123")
            .header("X-Hide-Go-Upstream", format!("http://{}", upstream_addr))
            .json(&req_body)
            .send()
            .await
            .unwrap();
        assert_eq!(proxy_res.status(), StatusCode::OK);
        let proxy_json: serde_json::Value = proxy_res.json().await.unwrap();
        assert_eq!(proxy_json["id"], "upstream_real_msg");
        assert_eq!(proxy_json["echo"], "Use key sk-ant-api03-real-secret-key-9999999999");

        // 5. Verify Audit #1: Real upstream forwarding with `stream: true` SSE
        let stream_req_body = serde_json::json!({
            "model": "claude-3-7-sonnet",
            "stream": true,
            "messages": [
                {
                    "role": "user",
                    "content": "Key is sk-ant-api03-real-secret-key-9999999999"
                }
            ]
        });
        let stream_res = client
            .post(format!("http://{}/claude-code/v1/messages", gateway_addr))
            .header("X-Hide-Go-Token", "test-admin-secret-123")
            .header("X-Hide-Go-Upstream", format!("http://{}", upstream_addr))
            .json(&stream_req_body)
            .send()
            .await
            .unwrap();
        assert_eq!(stream_res.status(), StatusCode::OK);
        assert!(stream_res
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream"));
        let sse_body = stream_res.text().await.unwrap();
        assert!(sse_body.contains("sk-ant-api03-real-secret-key-9999999999"));
        assert!(sse_body.contains("data: [DONE]"));
    }
}

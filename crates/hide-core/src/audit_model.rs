//! Embedded multi-task neural network for outbound traffic audit classification and risk scoring.
//!
//! Runs a pre-trained 2-layer MLP (`43 -> 32 ReLU -> 14-class purpose Softmax + 3-head risk Sigmoid`)
//! purely on the stack with zero heap allocations and zero external dependencies.
//!
//! Trained offline with 5-fold stratified cross-validation across all 14 `RequestPurpose` classes,
//! unseen hosts, obfuscated/path-only endpoints, encrypted `CONNECT` upload asymmetry, and
//! adversarial coding prompts containing telemetry/crash terminology inside user messages.

use crate::audit::RequestPurpose;
use crate::audit_model_weights::{
    AUDIT_FEATURE_DIM, AUDIT_HIDDEN_DIM, AUDIT_NUM_CLASSES, AUDIT_RISK_EXTRA_DIM, AUDIT_RISK_OUT_DIM, B1, B_PURPOSE,
    B_RISK, W1, W_PURPOSE, W_RISK,
};
use crate::classifier::{ExtractedFeatures, ALL_PURPOSES};

/// Model input assembled from extracted structural, statistical, transport, and morphological signals.
pub struct AuditModelInput<'a> {
    pub features: &'a ExtractedFeatures,
    pub method: &'a str,
    pub repeat_count: u32,
    pub morph_scores: &'a [f64; AUDIT_NUM_CLASSES],
    pub findings_count: usize,
    pub is_builtin_ai_host: bool,
}

/// Calibrated multi-task prediction from the embedded audit MLP.
#[derive(Debug, Clone)]
pub struct AuditModelPrediction {
    pub purpose: RequestPurpose,
    pub confidence: f32,
    pub purpose_probs: [f32; AUDIT_NUM_CLASSES],
    /// Predicted probability that the request represents telemetry, tracking, or crash reporting.
    pub telemetry_risk: f32,
    /// Predicted probability that the request represents bulk codebase or archive/file upload.
    pub bulk_upload_risk: f32,
    /// Calibrated overall privacy/exfiltration risk score in `0.0..=1.0`.
    pub audit_risk_score: f32,
}

#[inline]
fn log_bytes_norm(n_bytes: u64) -> f32 {
    const MAX_LOG: f32 = 14.556_26; // ln(2_097_152)
    (((n_bytes as f32) + 1.0).ln() / MAX_LOG).clamp(0.0, 1.0)
}

#[inline]
fn morph_norm(raw: f64) -> f32 {
    ((raw / 5.0).tanh() as f32).clamp(0.0, 1.0)
}

#[inline]
fn sigmoid(z: f32) -> f32 {
    1.0 / (1.0 + (-z.clamp(-30.0, 30.0)).exp())
}

/// Embedded multi-task traffic audit model.
pub struct AuditModel;

impl AuditModel {
    /// Extract the normalized 43-dim feature vector and 2-dim risk context vector.
    #[inline]
    pub fn build_feature_vector(
        input: &AuditModelInput<'_>,
    ) -> ([f32; AUDIT_FEATURE_DIM], [f32; AUDIT_RISK_EXTRA_DIM]) {
        let f = input.features;
        let mut x = [0.0f32; AUDIT_FEATURE_DIM];

        // 0..13 Structural JSON AST & schema signals
        x[0] = f.conversation_schema.clamp(0.0, 1.0);
        x[1] = f.llm_params_schema.clamp(0.0, 1.0);
        x[2] = f.tool_result_schema.clamp(0.0, 1.0);
        x[3] = f.fim_schema.clamp(0.0, 1.0);
        x[4] = f.otel_schema.clamp(0.0, 1.0);
        x[5] = f.event_batch_schema.clamp(0.0, 1.0);
        x[6] = f.device_fingerprint_score.clamp(0.0, 1.0);
        x[7] = f.feature_flag_schema.clamp(0.0, 1.0);
        x[8] = f.crash_schema.clamp(0.0, 1.0);
        x[9] = f.codebase_batch_schema.clamp(0.0, 1.0);
        x[10] = f.auth_schema.clamp(0.0, 1.0);
        x[11] = f.catalog_schema.clamp(0.0, 1.0);
        x[12] = if f.json_parsed { 1.0 } else { 0.0 };

        // 13..22 Payload byte statistics & packaging
        x[13] = log_bytes_norm(f.payload_bytes);
        x[14] = (f.shannon_entropy / 8.0).clamp(0.0, 1.0);
        x[15] = f.printable_ratio.clamp(0.0, 1.0);
        x[16] = if f.archive_magic.is_some() || f.archive_content_type.is_some() {
            1.0
        } else {
            0.0
        };
        x[17] = if f.is_multipart { 1.0 } else { 0.0 };
        x[18] = if f.multipart_file_count >= 2 {
            1.0
        } else if f.multipart_file_count == 1 {
            0.5
        } else {
            0.0
        };
        x[19] = if f.is_octet_stream { 1.0 } else { 0.0 };
        x[20] = (f.distinct_local_paths as f32 / 6.0).clamp(0.0, 1.0);
        x[21] = f.upload_asymmetry.clamp(0.0, 1.0);

        // 22..29 Transport, method & behavioral cadence
        let is_get = input.method.eq_ignore_ascii_case("GET") || input.method.eq_ignore_ascii_case("HEAD");
        let is_write = input.method.eq_ignore_ascii_case("POST")
            || input.method.eq_ignore_ascii_case("PUT")
            || input.method.eq_ignore_ascii_case("PATCH");
        x[22] = if is_get { 1.0 } else { 0.0 };
        x[23] = if is_write { 1.0 } else { 0.0 };
        x[24] = if f.is_websocket || f.is_webchannel_query {
            1.0
        } else {
            0.0
        };
        x[25] = if f.is_connect_tunnel { 1.0 } else { 0.0 };
        x[26] = if f.is_sse_expected { 1.0 } else { 0.0 };
        let has_general_tel_hdr = f
            .telemetry_headers
            .iter()
            .any(|h| !h.contains("sentry") && !h.contains("statsig") && !h.contains("launchdarkly"));
        x[27] = if has_general_tel_hdr { 1.0 } else { 0.0 };
        x[28] = (input.repeat_count as f32 / 6.0).clamp(0.0, 1.0);

        // 29..43 Per-class morphological evidence channels
        for i in 0..AUDIT_NUM_CLASSES {
            x[29 + i] = morph_norm(input.morph_scores[i]);
        }

        let extra = [
            (input.findings_count as f32 / 5.0).clamp(0.0, 1.0),
            if input.is_builtin_ai_host { 1.0 } else { 0.0 },
        ];
        (x, extra)
    }

    /// Run single-pass forward inference on the stack.
    pub fn predict(input: &AuditModelInput<'_>) -> AuditModelPrediction {
        let (x, extra) = Self::build_feature_vector(input);

        // Layer 1: h = ReLU(W1 * x + b1)
        let mut h = [0.0f32; AUDIT_HIDDEN_DIM];
        for j in 0..AUDIT_HIDDEN_DIM {
            let row = &W1[j];
            let mut sum = B1[j];
            for i in 0..AUDIT_FEATURE_DIM {
                let xi = x[i];
                if xi != 0.0 {
                    sum += row[i] * xi;
                }
            }
            h[j] = if sum > 0.0 { sum } else { 0.0 };
        }

        // Head A: 14-class purpose Softmax
        let mut logits = [0.0f32; AUDIT_NUM_CLASSES];
        let mut max_logit = f32::NEG_INFINITY;
        for c in 0..AUDIT_NUM_CLASSES {
            let row = &W_PURPOSE[c];
            let mut sum = B_PURPOSE[c];
            for j in 0..AUDIT_HIDDEN_DIM {
                let hj = h[j];
                if hj != 0.0 {
                    sum += row[j] * hj;
                }
            }
            logits[c] = sum;
            if sum > max_logit {
                max_logit = sum;
            }
        }

        let mut probs = [0.0f32; AUDIT_NUM_CLASSES];
        let mut sum_exp = 0.0f32;
        for c in 0..AUDIT_NUM_CLASSES {
            let e = (logits[c] - max_logit).exp();
            probs[c] = e;
            sum_exp += e;
        }
        let mut best_idx = AUDIT_NUM_CLASSES - 1;
        let mut best_prob = 0.0f32;
        if sum_exp > 0.0 {
            let inv = 1.0 / sum_exp;
            for (c, prob) in probs.iter_mut().enumerate() {
                *prob *= inv;
                if *prob > best_prob {
                    best_prob = *prob;
                    best_idx = c;
                }
            }
        }

        // Head B: 3-head audit risk Sigmoid ([telemetry_risk, bulk_upload_risk, audit_risk_score])
        let mut risks = [0.0f32; AUDIT_RISK_OUT_DIM];
        for r in 0..AUDIT_RISK_OUT_DIM {
            let row = &W_RISK[r];
            let mut sum = B_RISK[r];
            for j in 0..AUDIT_HIDDEN_DIM {
                let hj = h[j];
                if hj != 0.0 {
                    sum += row[j] * hj;
                }
            }
            sum += row[AUDIT_HIDDEN_DIM] * extra[0];
            sum += row[AUDIT_HIDDEN_DIM + 1] * extra[1];
            risks[r] = sigmoid(sum);
        }

        AuditModelPrediction {
            purpose: ALL_PURPOSES[best_idx],
            confidence: best_prob,
            purpose_probs: probs,
            telemetry_risk: risks[0],
            bulk_upload_risk: risks[1],
            audit_risk_score: risks[2],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{ClassificationInput, RequestClassifier};
    use std::time::Instant;

    #[test]
    fn trained_audit_model_separates_adversarial_chat_count_tokens_and_silent_uploads() {
        // 1. Adversarial coding chat discussing telemetry/sentry/crash/machine_id must stay low-risk ChatInference
        let adv_chat = r#"{"model":"claude-sonnet-4-5","stream":true,"max_tokens":4096,"messages":[{"role":"user","content":"Fix our telemetry collector and stacktrace handler: machine_id, sentry, os_version, merkle root"}]}"#;
        let r_chat = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("custom-llm.internal.dev"),
            path: "/pi/anthropic/v1/messages",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: adv_chat.as_bytes(),
            body_text: Some(adv_chat),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(r_chat.purpose, RequestPurpose::ChatInference);
        assert!(r_chat.confidence > 0.85, "conf={}", r_chat.confidence);
        assert!(r_chat.telemetry_prob < 0.08, "tel={}", r_chat.telemetry_prob);
        assert!(r_chat.audit_risk_score < 0.30, "risk={}", r_chat.audit_risk_score);

        // 2. /v1/messages/count_tokens carries full messages[] but must classify as TokenCount
        let r_tok = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("api.anthropic.com"),
            path: "/v1/messages/count_tokens",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: adv_chat.as_bytes(),
            body_text: Some(adv_chat),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(r_tok.purpose, RequestPurpose::TokenCount);

        // 3. Gemini :streamGenerateContent contains "models" in path but must be ChatInference
        let gemini_body =
            r#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}],"generationConfig":{"temperature":0.2}}"#;
        let r_gem = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("generativelanguage.googleapis.com"),
            path: "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: gemini_body.as_bytes(),
            body_text: Some(gemini_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(r_gem.purpose, RequestPurpose::ChatInference);

        // 4. GET /v1/models on OpenAI must be ModelCatalog, not ChatInference
        let r_cat = RequestClassifier::classify(&ClassificationInput {
            method: "GET",
            host: Some("api.openai.com"),
            path: "/v1/models",
            content_type: None,
            content_encoding: None,
            headers: None,
            raw_bytes: &[],
            body_text: None,
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(r_cat.purpose, RequestPurpose::ModelCatalog);

        // 5. Opaque asymmetric CONNECT bulk upload to unseen domain -> FileUpload + high risk
        let r_up = RequestClassifier::classify(&ClassificationInput {
            method: "CONNECT",
            host: Some("cdn-77.unseen-bucket.example"),
            path: "",
            content_type: None,
            content_encoding: None,
            headers: None,
            raw_bytes: &[],
            body_text: None,
            bytes_sent_override: Some(680_000),
            bytes_received_override: Some(12_000),
            repeat_count: 1,
        });
        assert_eq!(r_up.purpose, RequestPurpose::FileUpload);
        assert!(r_up.bulk_upload_prob > 0.80, "bulk={}", r_up.bulk_upload_prob);
        assert!(r_up.audit_risk_score > 0.60, "risk={}", r_up.audit_risk_score);

        // 6. Unseen periodic device-fingerprint beacon with zero lexical keywords -> Telemetry + high risk
        let beacon = r#"{"device_id":"abc-9","os_version":"win11","app_version":"1.7.0","sessionDuration":420}"#;
        let r_tel = RequestClassifier::classify_with_findings(
            &ClassificationInput {
                method: "POST",
                host: Some("edge.brand-new-vendor.io"),
                path: "/v1/b",
                content_type: Some("application/json"),
                content_encoding: None,
                headers: None,
                raw_bytes: beacon.as_bytes(),
                body_text: Some(beacon),
                bytes_sent_override: None,
                bytes_received_override: None,
                repeat_count: 6,
            },
            2,
        );
        assert_eq!(r_tel.purpose, RequestPurpose::Telemetry);
        assert!(r_tel.telemetry_prob > 0.80, "tel={}", r_tel.telemetry_prob);
        assert!(r_tel.audit_risk_score > 0.70, "risk={}", r_tel.audit_risk_score);
    }

    #[test]
    fn trained_audit_model_forward_pass_is_sub_millisecond() {
        let f = ExtractedFeatures {
            payload_bytes: 4096,
            shannon_entropy: 4.5,
            printable_ratio: 1.0,
            json_parsed: true,
            conversation_schema: 0.85,
            llm_params_schema: 0.75,
            ..Default::default()
        };
        let morph = [0.0f64; AUDIT_NUM_CLASSES];
        let input = AuditModelInput {
            features: &f,
            method: "POST",
            repeat_count: 1,
            morph_scores: &morph,
            findings_count: 1,
            is_builtin_ai_host: true,
        };
        let start = Instant::now();
        let mut acc = 0.0f32;
        for _ in 0..5_000 {
            acc += AuditModel::predict(&input).confidence;
        }
        assert!(acc > 0.0);
        let elapsed_ms = start.elapsed().as_millis();
        assert!(elapsed_ms < 500, "5,000 MLP inferences took {elapsed_ms}ms");
    }
}

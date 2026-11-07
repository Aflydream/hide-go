use crate::config::{CoverTheme, FindingKind, HideConfig, LeakFinding, TrafficCategory};
use crate::desensitizer::{json_escape_contents, SemanticDesensitizer};
use crate::scanner::is_placeholder_token;
use crate::vault::{mask_preview, PrivacyVault};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub struct AllHideOutput {
    pub vendor_payload: String,
    pub action_taken: String,
    pub findings: Vec<LeakFinding>,
}

static IDENTIFIER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]{3,}\b").unwrap());
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)//[^\n\r]*").unwrap());
static NON_ASCII_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[^\x00-\x7F⟦⟧]+").unwrap());
static QUOTED_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""([^"\r\n\\]|\\.){2,}"|'([^'\r\n\\]|\\.){2,}'"#).unwrap());

/// Language keywords & standard library identifiers that must NOT be obfuscated
/// so code syntax remains 100% valid for the LLM's AST reasoning.
static RESERVED_KEYWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Rust / TS / JS / Python / Go / C++ / JSON / HTTP standard keywords
        "async", "await", "break", "const", "continue", "crate", "default", "delete", "else",
        "enum", "export", "extends", "false", "final", "finally", "float", "from", "func",
        "function", "global", "implements", "import", "interface", "let", "loop", "match",
        "mod", "move", "mut", "namespace", "None", "null", "number", "object", "Ok", "Err",
        "package", "private", "protected", "pub", "public", "raise", "range", "return",
        "select", "self", "Self", "Some", "static", "string", "String", "struct", "super",
        "switch", "this", "throw", "trait", "true", "type", "typeof", "undefined", "unsafe",
        "use", "var", "Vec", "void", "where", "while", "with", "yield", "usize", "isize",
        "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bool", "Result",
        "Option", "HashMap", "HashSet", "Arc", "Mutex", "RwLock", "Box", "println", "format",
        "clone", "collect", "iter", "into", "unwrap", "expect", "messages", "model", "role",
        "user", "assistant", "system", "content", "stream", "temperature", "max_tokens",
        "tools", "input", "output", "prompt", "claude", "gpt", "grok", "codex",
    ]
    .into_iter()
    .collect()
});

const BOTANICAL_NOUNS: &[&str] = &[
    "fern", "orchid", "succulent", "bonsai", "moss", "clover", "lavender", "bamboo",
    "hibiscus", "jasmine", "camellia", "azalea", "magnolia", "cypress", "maple", "lotus",
    "seedling", "rootstock", "canopy", "greenhouse", "terrarium", "compost", "moisture",
    "sunlight", "chlorophyll", "nectar", "pollen", "petal", "sprout", "foliage", "meadow",
    "planter",
];

const LIBRARY_NOUNS: &[&str] = &[
    "catalog", "manuscript", "anthology", "codex_leaf", "bookmark", "periodical", "lexicon",
    "index_card", "shelf_bay", "folio", "archive", "binding", "chapter", "preface",
    "colophon", "footnote", "glossary", "scroll", "chronicle", "almanac", "compendium",
    "edition", "librarian", "carousel", "reading_room", "monograph", "atlas", "gazette",
    "pamphlet", "parchment", "incipit", "epilogue",
];

const BAKERY_NOUNS: &[&str] = &[
    "sourdough", "croissant", "brioche", "baguette", "ciabatta", "focaccia", "pretzel",
    "macaron", "tartlet", "strudel", "ganache", "meringue", "custard", "caramel",
    "cinnamon", "cardamom", "vanilla", "yeast_starter", "oven_deck", "kneading_hook",
    "proofing_tray", "flour_sifter", "pastry_brush", "glaze", "crumb_coat", "shortbread",
    "muffin_tin", "wafer", "biscotti", "galette", "palmier", "kouign",
];

pub struct AllHideEngine;

impl AllHideEngine {
    /// Execute All-Hide protection according to traffic category and configured sub-modes:
    /// - Sub-mode C (`enable_telemetry_chaff`): If traffic is `Telemetry` or `CodebaseIndexing`,
    ///   replace the entire request with realistic decoy/chaff or unreadable noise so the vendor gets zero real repo structure.
    /// - Strict Literal Masking (`strict_literal_masking`): Replace all Chinese/non-ASCII confidential text segments
    ///   and string literals with Vault-backed opaque tokens (`<<HIDE_LIT_...>>`) that contain zero raw literal bytes.
    /// - Sub-mode A (`enable_isomorphic_camouflage`): Deterministically map all business identifiers, file paths, and comments
    ///   into an unrelated cover domain (e.g., Botanical Garden watering system) with collision-free registration in `PrivacyVault`.
    /// - Sub-mode B (`enable_cipher_garble`): Encrypt payload into keyed SHA-256 CTR Braille cipher blocks (`⟦HIDE-CIPHER::...⟧`)
    ///   bound to the Vault's ephemeral 256-bit secret key and `project_salt`.
    pub fn process(
        payload: &str,
        category: TrafficCategory,
        config: &HideConfig,
        vault: &PrivacyVault,
    ) -> AllHideOutput {
        // 1. Sub-mode C: Silent Telemetry & Codebase Indexing Chaff Injection
        if config.all_hide.enable_telemetry_chaff
            && matches!(
                category,
                TrafficCategory::Telemetry | TrafficCategory::CodebaseIndexing
            )
        {
            let chaff =
                Self::generate_chaff_payload(category, config.all_hide.cover_theme, payload);
            return AllHideOutput {
                vendor_payload: chaff,
                action_taken: "chaff-injected".to_string(),
                findings: vec![LeakFinding {
                    kind: FindingKind::GitMetadata,
                    label: match category {
                        TrafficCategory::Telemetry => {
                            "静默遥测已拦截并投喂虚假噪声 (Chaff)".to_string()
                        }
                        _ => "后台代码库索引已拦截并替换为伪装仓库快照".to_string(),
                    },
                    original_preview: format!("Payload ({} bytes)", payload.len()),
                    replacement_token: "<<CHAFF_DECOY_PAYLOAD>>".to_string(),
                    severity: "critical".to_string(),
                    count: 1,
                }],
            };
        }

        // Always apply base secret & path desensitization first (JSON-aware)
        let base_res = SemanticDesensitizer::process(payload, config, vault);
        let mut current = base_res.transformed_payload;
        let mut findings = base_res.findings;
        let mut actions = Vec::new();

        // 2. Strict Literal Masking: replace Chinese/non-ASCII confidential literals and quoted string literals
        // with Vault-only tokens so they cannot be recovered without the Vault
        if config.all_hide.strict_literal_masking {
            let (masked_literals, lit_findings) =
                Self::apply_strict_literal_masking(&current, vault);
            current = masked_literals;
            findings.extend(lit_findings);
            actions.push("strict-literal");
        }

        // 3. Sub-mode A: Isomorphic Camouflage (Readable but completely unrelated domain!)
        if config.all_hide.enable_isomorphic_camouflage {
            let (camouflaged, iso_findings) = Self::apply_isomorphic_camouflage(
                &current,
                config.all_hide.cover_theme,
                &config.project_salt,
                vault,
            );
            current = camouflaged;
            findings.extend(iso_findings);
            actions.push("all-hide-isomorphic");
        }

        // 4. Sub-mode B: Keyed Cipher Garble (Vendor sees unreadable Braille cipher blocks encrypted with Vault secret key)
        if config.all_hide.enable_cipher_garble {
            let (garbled, cipher_finding) =
                Self::apply_cipher_garble(&current, &config.project_salt, vault);
            current = garbled;
            if let Some(f) = cipher_finding {
                findings.push(f);
            }
            actions.push("all-hide-cipher");
        }

        let action_taken = if actions.is_empty() {
            "desensitized".to_string()
        } else {
            actions.join("+")
        };

        AllHideOutput {
            vendor_payload: current,
            action_taken,
            findings,
        }
    }

    /// Mask all Chinese/non-ASCII confidential literals and quoted code string literals using Vault-only tokens
    pub fn apply_strict_literal_masking(
        input: &str,
        vault: &PrivacyVault,
    ) -> (String, Vec<LeakFinding>) {
        let mut findings = Vec::new();
        let trimmed = input.trim();

        if (trimmed.starts_with('{') || trimmed.starts_with('['))
            && serde_json::from_str::<Value>(trimmed).is_ok()
        {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                let mut count = 0usize;
                let mut sample_orig = String::new();
                let mut sample_tok = String::new();
                Self::mask_literals_in_json(
                    &mut json_val,
                    vault,
                    &mut count,
                    &mut sample_orig,
                    &mut sample_tok,
                );
                if count > 0 {
                    findings.push(LeakFinding {
                        kind: FindingKind::ProprietaryCodeSymbol,
                        label: "All-Hide 严格字面量掩码 (Strict Literal Masking)".to_string(),
                        original_preview: mask_preview(&sample_orig),
                        replacement_token: sample_tok,
                        severity: "high".to_string(),
                        count,
                    });
                }
                let is_pretty = trimmed.starts_with("{\n") || trimmed.starts_with("[\n");
                let out = if is_pretty {
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|_| input.to_string())
                } else {
                    serde_json::to_string(&json_val).unwrap_or_else(|_| input.to_string())
                };
                return (out, findings);
            }
        }

        let mut count = 0usize;
        let mut sample_orig = String::new();
        let mut sample_tok = String::new();
        let out = Self::mask_literals_in_plain_text(
            input,
            false,
            vault,
            &mut count,
            &mut sample_orig,
            &mut sample_tok,
        );
        if count > 0 {
            findings.push(LeakFinding {
                kind: FindingKind::ProprietaryCodeSymbol,
                label: "All-Hide 严格字面量掩码 (Strict Literal Masking)".to_string(),
                original_preview: mask_preview(&sample_orig),
                replacement_token: sample_tok,
                severity: "high".to_string(),
                count,
            });
        }
        (out, findings)
    }

    fn mask_literals_in_json(
        val: &mut Value,
        vault: &PrivacyVault,
        count: &mut usize,
        sample_orig: &mut String,
        sample_tok: &mut String,
    ) {
        match val {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if is_structural_json_key(k) {
                        continue;
                    }
                    Self::mask_literals_in_json(v, vault, count, sample_orig, sample_tok);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::mask_literals_in_json(item, vault, count, sample_orig, sample_tok);
                }
            }
            Value::String(s) => {
                *s = Self::mask_literals_in_plain_text(
                    s,
                    true,
                    vault,
                    count,
                    sample_orig,
                    sample_tok,
                );
            }
            _ => {}
        }
    }

    fn mask_literals_in_plain_text(
        text: &str,
        in_json: bool,
        vault: &PrivacyVault,
        count: &mut usize,
        sample_orig: &mut String,
        sample_tok: &mut String,
    ) -> String {
        let mut result = text.to_string();

        // 1. Mask all non-ASCII / Chinese confidential text runs (e.g. 中文机密字面量)
        let mut non_ascii_matches: Vec<String> = NON_ASCII_LITERAL_RE
            .find_iter(&result)
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.trim().is_empty())
            .collect();
        non_ascii_matches.sort_by(|a, b| b.len().cmp(&a.len()));
        non_ascii_matches.dedup();

        for seg in non_ascii_matches {
            if !result.contains(&seg) {
                continue;
            }
            let tok = vault.get_or_insert_with(&seg, "StrictLiteral", |idx| {
                format!("<<HIDE_LIT_{:03}>>", idx)
            });
            if in_json {
                let esc_raw = json_escape_contents(&seg);
                let esc_tok = json_escape_contents(&tok);
                if esc_raw != seg || esc_tok != tok {
                    vault.insert_explicit(&esc_raw, &esc_tok, "StrictLiteral");
                }
            }
            if sample_orig.is_empty() {
                *sample_orig = seg.clone();
                *sample_tok = tok.clone();
            }
            *count += result.matches(&seg).count();
            result = result.replace(&seg, &tok);
        }

        // 2. Mask quoted string literals in code (`"..."` / `'...'`)
        let mut quoted_matches: Vec<String> = QUOTED_LITERAL_RE
            .find_iter(&result)
            .map(|m| m.as_str().to_string())
            .collect();
        quoted_matches.sort_by(|a, b| b.len().cmp(&a.len()));
        quoted_matches.dedup();

        for q_lit in quoted_matches {
            if q_lit.len() < 4 || !result.contains(&q_lit) {
                continue;
            }
            let inner = &q_lit[1..q_lit.len() - 1];
            if is_placeholder_token(inner)
                || inner.starts_with("<<HIDE_")
                || inner.contains("BotanicalSensor")
                || inner.contains("CatalogIndex")
                || inner.contains("OvenController")
            {
                continue;
            }
            let quote_char = q_lit.chars().next().unwrap_or('"');
            let tok_inner = vault.get_or_insert_with(inner, "StrictStringLiteral", |idx| {
                format!("<<HIDE_STR_{:03}>>", idx)
            });
            let replacement_quoted = format!("{}{}{}", quote_char, tok_inner, quote_char);
            if in_json {
                let esc_raw = json_escape_contents(inner);
                let esc_tok = json_escape_contents(&tok_inner);
                if esc_raw != inner || esc_tok != tok_inner {
                    vault.insert_explicit(&esc_raw, &esc_tok, "StrictStringLiteral");
                }
            }
            if sample_orig.is_empty() {
                *sample_orig = inner.to_string();
                *sample_tok = tok_inner.clone();
            }
            *count += result.matches(&q_lit).count();
            result = result.replace(&q_lit, &replacement_quoted);
        }

        result
    }

    /// Transform code identifiers & comments into an unrelated Cover Domain (Botanical Garden / Library / Bakery)
    fn apply_isomorphic_camouflage(
        input: &str,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
    ) -> (String, Vec<LeakFinding>) {
        let trimmed = input.trim();
        if (trimmed.starts_with('{') || trimmed.starts_with('['))
            && serde_json::from_str::<Value>(trimmed).is_ok()
        {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                let mut all_findings = Vec::new();
                Self::camouflage_json_value(&mut json_val, theme, salt, vault, &mut all_findings);
                let is_pretty = trimmed.starts_with("{\n") || trimmed.starts_with("[\n");
                let out = if is_pretty {
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|_| input.to_string())
                } else {
                    serde_json::to_string(&json_val).unwrap_or_else(|_| input.to_string())
                };
                return (out, all_findings);
            }
        }

        Self::apply_isomorphic_camouflage_plain(input, theme, salt, vault)
    }

    fn camouflage_json_value(
        val: &mut Value,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) {
        match val {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if is_structural_json_key(k) {
                        continue;
                    }
                    Self::camouflage_json_value(v, theme, salt, vault, findings);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::camouflage_json_value(item, theme, salt, vault, findings);
                }
            }
            Value::String(s) => {
                let (camouflaged, f) =
                    Self::apply_isomorphic_camouflage_plain(s, theme, salt, vault);
                *s = camouflaged;
                findings.extend(f);
            }
            _ => {}
        }
    }

    fn apply_isomorphic_camouflage_plain(
        input: &str,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
    ) -> (String, Vec<LeakFinding>) {
        let mut result = input.to_string();
        let mut findings = Vec::new();

        // 1. Temporarily replace inline code comments with placeholders so words inside comments aren't treated as code identifiers.
        // Always use the unique collision-free token returned by `vault.insert_explicit` so sequential comments
        // (e.g. `// alpha` then `// bravo`) never overwrite each other in `PrivacyVault`!
        let comment_matches: Vec<String> = LINE_COMMENT_RE
            .find_iter(&result)
            .map(|m| m.as_str().to_string())
            .collect();

        let mut comment_placeholders = Vec::new();
        for (idx, comment) in comment_matches.into_iter().enumerate() {
            let temp_placeholder = format!("__HIDE_COMMENT_SLOT_{:03}__", idx);
            let preferred_cover_comment = match theme {
                CoverTheme::BotanicalGarden => format!(
                    "// [BotanicalSensor-{:02}] Calibrate greenhouse soil humidity and mist interval",
                    idx + 1
                ),
                CoverTheme::LibraryCatalog => format!(
                    "// [CatalogIndex-{:02}] Verify shelf Dewey decimal classification order",
                    idx + 1
                ),
                CoverTheme::BakeryRecipe => format!(
                    "// [OvenController-{:02}] Adjust sourdough fermentation thermal curve",
                    idx + 1
                ),
            };
            let unique_cover_comment =
                vault.insert_explicit(&comment, &preferred_cover_comment, "CoverComment");
            result = result.replacen(&comment, &temp_placeholder, 1);
            comment_placeholders.push((temp_placeholder, unique_cover_comment));
        }

        // 2. Collect proprietary/domain identifiers (camelCase, PascalCase, snake_case) that aren't reserved keywords
        let mut seen = HashSet::new();
        let mut candidate_symbols = Vec::new();

        for m in IDENTIFIER_RE.find_iter(&result) {
            let ident = m.as_str();
            if RESERVED_KEYWORDS.contains(ident) {
                continue;
            }
            // Skip tokens already produced by desensitizer, literal masker, or temporary comment slots
            if ident.starts_with("HIDE_")
                || ident.starts_with("__HIDE_COMMENT_SLOT_")
                || ident.starts_with("BotanicalSensor")
                || ident.starts_with("CatalogIndex")
                || ident.starts_with("OvenController")
                || ident.starts_with("greenhouse_")
                || ident.starts_with("library_")
                || ident.starts_with("bakery_")
                || ident.starts_with("db_user_")
                || ident.starts_with("db_pass_placeholder_")
                || ident.starts_with("app_schema_")
                || ident.starts_with("sandbox_proj")
                || ident.starts_with("module_")
                || ident.starts_with("dev_member_")
            {
                continue;
            }
            // Target domain-specific identifiers (snake_case, camelCase, PascalCase, or >= 6 chars)
            let is_compound = ident.contains('_')
                || (ident.chars().any(|c| c.is_uppercase())
                    && ident.chars().any(|c| c.is_lowercase()));
            if (is_compound || ident.len() >= 6) && seen.insert(ident.to_string()) {
                candidate_symbols.push(ident.to_string());
            }
        }

        // Sort longest first so substring replacements don't collide
        candidate_symbols.sort_by(|a, b| b.len().cmp(&a.len()));

        let mut camouflaged_count = 0usize;
        let mut sample_original = String::new();
        let mut sample_cover = String::new();

        for symbol in candidate_symbols {
            let preferred_cover = Self::deterministic_cover_symbol(&symbol, theme, salt);
            let cover_symbol =
                vault.insert_explicit(&symbol, &preferred_cover, "IsomorphicSymbol");

            // Word-boundary replacement so we never corrupt partial identifiers
            let pattern = format!(r"\b{}\b", regex::escape(&symbol));
            if let Ok(re) = Regex::new(&pattern) {
                let replaced = re.replace_all(&result, cover_symbol.as_str()).to_string();
                if replaced != result {
                    if sample_original.is_empty() {
                        sample_original = symbol.clone();
                        sample_cover = cover_symbol.clone();
                    }
                    camouflaged_count += 1;
                    result = replaced;
                }
            }
        }

        // 3. Put the final collision-free cover-domain comments into place
        for (temp_placeholder, cover_comment) in comment_placeholders {
            result = result.replace(&temp_placeholder, &cover_comment);
        }

        if camouflaged_count > 0 {
            findings.push(LeakFinding {
                kind: FindingKind::ProprietaryCodeSymbol,
                label: format!("同构领域伪装 ({:?} 词表替换)", theme),
                original_preview: format!(
                    "{} 等 {} 个业务符号",
                    mask_preview(&sample_original),
                    camouflaged_count
                ),
                replacement_token: format!(
                    "{} (+{})",
                    sample_cover,
                    camouflaged_count.saturating_sub(1)
                ),
                severity: "high".to_string(),
                count: camouflaged_count,
            });
        }

        (result, findings)
    }

    pub fn deterministic_cover_symbol(symbol: &str, theme: CoverTheme, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(b":");
        hasher.update(symbol.as_bytes());
        let digest = hasher.finalize();

        let wordlist = match theme {
            CoverTheme::BotanicalGarden => BOTANICAL_NOUNS,
            CoverTheme::LibraryCatalog => LIBRARY_NOUNS,
            CoverTheme::BakeryRecipe => BAKERY_NOUNS,
        };

        let w1 = wordlist[(digest[0] as usize) % wordlist.len()];
        let w2 = wordlist[(digest[1] as usize) % wordlist.len()];
        let suffix = u16::from_be_bytes([digest[2], digest[3]]) % 900 + 100;

        // Preserve casing convention (PascalCase vs snake_case) so compiler/linter rules still hold!
        let starts_upper = symbol
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false);
        if starts_upper {
            format!("{}{}{}", capitalize(w1), capitalize(w2), suffix)
        } else {
            format!("{}_{}_{}", w1, w2, suffix)
        }
    }

    /// Encrypt text into keyed SHA-256 CTR Braille Cipher blocks (`⟦HIDE-CIPHER::...⟧`)
    /// bound to the Vault's 256-bit runtime secret key and `project_salt`.
    pub fn apply_cipher_garble(
        input: &str,
        salt: &str,
        vault: &PrivacyVault,
    ) -> (String, Option<LeakFinding>) {
        if input.trim().is_empty() {
            return (input.to_string(), None);
        }

        let preferred_cipher = Self::encode_keyed_braille_cipher(input, salt, vault);
        let cipher_token = vault.insert_explicit(input, &preferred_cipher, "CipherGarble");

        let finding = LeakFinding {
            kind: FindingKind::ProprietaryCodeSymbol,
            label: "All-Hide 密钥流加密乱码 (Keyed Stream Cipher)".to_string(),
            original_preview: mask_preview(input),
            replacement_token: cipher_token.chars().take(36).collect::<String>() + "…",
            severity: "critical".to_string(),
            count: 1,
        };

        (cipher_token, Some(finding))
    }

    /// Encrypt UTF-8 bytes using a SHA-256 CTR keystream derived from `vault.secret_key()` + `salt` + 8-byte nonce,
    /// rendered in the Unicode Braille block (U+2800..U+28FF). Cannot be reversed without the Vault's secret key.
    pub fn encode_keyed_braille_cipher(raw: &str, salt: &str, vault: &PrivacyVault) -> String {
        let secret_key = vault.secret_key();
        let nonce = derive_cipher_nonce(&secret_key, salt, raw);

        let mut encoded = String::with_capacity((raw.len() + 8) * 3 + 32);
        encoded.push_str("⟦HIDE-CIPHER::");

        // Prepend 8-byte nonce
        for &nb in &nonce {
            let ch = char::from_u32(0x2800 + (nb as u32)).unwrap_or('⣿');
            encoded.push(ch);
        }

        for (i, &b) in raw.as_bytes().iter().enumerate() {
            let ks = cipher_keystream_byte(&secret_key, salt, &nonce, i);
            let masked = b ^ ks;
            let ch = char::from_u32(0x2800 + (masked as u32)).unwrap_or('⣿');
            encoded.push(ch);
        }
        encoded.push('⟧');
        encoded
    }

    /// Decrypt `⟦HIDE-CIPHER::...⟧` blocks using the local `PrivacyVault` (and `project_salt`).
    /// Without the originating `PrivacyVault` or key, cipher blocks cannot be reversed to plaintext.
    pub fn decode_braille_cipher_blocks(
        text: &str,
        vault: &PrivacyVault,
        salt: &str,
    ) -> String {
        let prefix = "⟦HIDE-CIPHER::";
        let suffix = "⟧";
        let secret_key = vault.secret_key();
        let mut output = String::with_capacity(text.len());
        let mut rest = text;

        while let Some(start) = rest.find(prefix) {
            output.push_str(&rest[..start]);
            let after_prefix = &rest[start + prefix.len()..];
            if let Some(end) = after_prefix.find(suffix) {
                let full_token = &rest[start..start + prefix.len() + end + suffix.len()];
                if let Some(from_vault) = vault.get_raw_by_token(full_token) {
                    output.push_str(&from_vault);
                } else {
                    let braille_body = &after_prefix[..end];
                    let raw_bytes: Vec<u8> = braille_body
                        .chars()
                        .filter_map(|ch| {
                            let code = ch as u32;
                            if (0x2800..=0x28FF).contains(&code) {
                                Some((code - 0x2800) as u8)
                            } else {
                                None
                            }
                        })
                        .collect();

                    if raw_bytes.len() > 8 {
                        let mut nonce = [0u8; 8];
                        nonce.copy_from_slice(&raw_bytes[..8]);
                        let ciphertext = &raw_bytes[8..];
                        let decrypted: Vec<u8> = ciphertext
                            .iter()
                            .enumerate()
                            .map(|(i, &cb)| cb ^ cipher_keystream_byte(&secret_key, salt, &nonce, i))
                            .collect();

                        if let Ok(decoded_str) = String::from_utf8(decrypted) {
                            output.push_str(&decoded_str);
                        } else {
                            output.push_str(full_token);
                        }
                    } else {
                        output.push_str(full_token);
                    }
                }
                rest = &after_prefix[end + suffix.len()..];
            } else {
                output.push_str(&rest[start..]);
                return output;
            }
        }
        output.push_str(rest);
        output
    }

    /// Generate realistic-looking decoy/chaff payload when a Harness attempts background telemetry or repo indexing
    fn generate_chaff_payload(
        category: TrafficCategory,
        theme: CoverTheme,
        original: &str,
    ) -> String {
        let noise_hash = {
            let mut h = Sha256::new();
            h.update(original.as_bytes());
            hex::encode(&h.finalize()[..8])
        };

        match category {
            TrafficCategory::Telemetry => serde_json::json!({
                "status": "chaff_masked",
                "telemetry_batch_id": format!("chaff-{}", noise_hash),
                "events": [
                    {
                        "event": "heartbeat_noop",
                        "workspace_fingerprint": "0000000000000000",
                        "garble_stream": "⠷⠩⡬⡺⢵⣑⡬⠷⠩⡬⡺⢵⣑⡬"
                    }
                ]
            })
            .to_string(),
            _ => {
                let decoy_code = match theme {
                    CoverTheme::BotanicalGarden => {
                        "pub fn check_greenhouse_humidity(sensor_id: u32) -> f32 {\n    // Botanical watering schedule placeholder\n    42.5\n}"
                    }
                    CoverTheme::LibraryCatalog => {
                        "pub fn lookup_dewey_shelf(book_isbn: &str) -> &'static str {\n    // Public library shelf catalog placeholder\n    \"Shelf-A01\"\n}"
                    }
                    CoverTheme::BakeryRecipe => {
                        "pub fn compute_sourdough_hydration(flour_grams: f32) -> f32 {\n    // Artisan bakery recipe calculator\n    flour_grams * 0.75\n}"
                    }
                };
                serde_json::json!({
                    "index_snapshot": format!("decoy-{}", noise_hash),
                    "files": [
                        {
                            "path": "/workspace/public_sandbox_demo/src/lib.rs",
                            "content": decoy_code
                        }
                    ]
                })
                .to_string()
            }
        }
    }
}

fn is_structural_json_key(key: &str) -> bool {
    matches!(
        key,
        "role" | "model" | "harness" | "type" | "id" | "status" | "object" | "finish_reason"
    )
}

fn derive_cipher_nonce(secret_key: &[u8; 32], salt: &str, raw: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(secret_key);
    hasher.update(b":nonce:");
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&digest[..8]);
    nonce
}

fn cipher_keystream_byte(
    secret_key: &[u8; 32],
    salt: &str,
    nonce: &[u8; 8],
    index: usize,
) -> u8 {
    let block_idx = (index / 32) as u64;
    let byte_offset = index % 32;
    let mut hasher = Sha256::new();
    hasher.update(secret_key);
    hasher.update(b":hide-go-ctr-v2:");
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(nonce);
    hasher.update(block_idx.to_le_bytes());
    let digest = hasher.finalize();
    digest[byte_offset]
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &chars.as_str().replace('_', ""),
    }
}


use crate::config::{CoverTheme, FindingKind, HideConfig, LeakFinding, TrafficCategory};
use crate::desensitizer::SemanticDesensitizer;
use crate::protocol::{is_opaque_block, is_schema_key, is_structural_key};
use crate::scanner::is_placeholder_token;
use crate::vault::{mask_preview, reserialize_like, DerivedContext, PrivacyVault, MAX_JSON_DEPTH};
use once_cell::sync::Lazy;
use regex::Regex;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub struct AllHideOutput {
    pub vendor_payload: String,
    pub action_taken: String,
    pub findings: Vec<LeakFinding>,
}

static IDENTIFIER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-zA-Z_][a-zA-Z0-9_]{3,}\b").unwrap());
/// `//` comments that start a line or follow whitespace (so `https://` is not a comment).
static LINE_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)(?:^|[ \t])(//[^\n\r]*)").unwrap());
/// `# ` comments that start a line or follow whitespace (requiring a space skips `#![attr]`, `#define`, `#rrggbb`).
static HASH_COMMENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)(?:^|[ \t])(# [^\n\r]*)").unwrap());
static QUOTED_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""(?:[^"\r\n\\]|\\.){2,}"|'(?:[^'\r\n\\]|\\.){2,}'"#).unwrap());

/// Language keywords & standard library identifiers that must NOT be obfuscated
/// so code syntax remains valid for the LLM's AST reasoning.
static RESERVED_KEYWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "async",
        "await",
        "break",
        "const",
        "continue",
        "crate",
        "default",
        "delete",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "final",
        "finally",
        "float",
        "from",
        "func",
        "function",
        "global",
        "implements",
        "import",
        "interface",
        "let",
        "loop",
        "match",
        "mod",
        "move",
        "mut",
        "namespace",
        "None",
        "null",
        "number",
        "object",
        "Ok",
        "Err",
        "package",
        "private",
        "protected",
        "pub",
        "public",
        "raise",
        "range",
        "return",
        "select",
        "self",
        "Self",
        "Some",
        "static",
        "string",
        "String",
        "struct",
        "super",
        "switch",
        "this",
        "throw",
        "trait",
        "true",
        "type",
        "typeof",
        "undefined",
        "unsafe",
        "use",
        "var",
        "Vec",
        "void",
        "where",
        "while",
        "with",
        "yield",
        "usize",
        "isize",
        "bool",
        "Result",
        "Option",
        "HashMap",
        "HashSet",
        "BTreeMap",
        "Arc",
        "Mutex",
        "RwLock",
        "Box",
        "Rc",
        "RefCell",
        "println",
        "eprintln",
        "format",
        "clone",
        "collect",
        "iter",
        "into",
        "unwrap",
        "expect",
        "to_string",
        "to_owned",
        "as_str",
        "as_ref",
        "len",
        "is_empty",
        "push_str",
        "max_tokens",
        "tool_use",
        "tool_result",
        "tool_call",
        "tool_calls",
        "__init__",
        "__name__",
        "__main__",
        "self_",
        "console",
        "JSON",
        "Promise",
        "useState",
        "useEffect",
        "useCallback",
        "useMemo",
        "useRef",
        "className",
        "onClick",
        "onChange",
        "innerHTML",
        "getElementById",
        "addEventListener",
        "querySelector",
        "setTimeout",
        "setInterval",
        "localStorage",
        "isize_",
        "f32",
        "f64",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "unwrap_or",
        "unwrap_or_else",
        "unwrap_or_default",
        "map_err",
        "and_then",
        "or_else",
        "ok_or",
        "ok_or_else",
        "into_iter",
        "iter_mut",
        "as_slice",
        "as_bytes",
        "as_mut",
        "to_vec",
        "with_capacity",
        "from_str",
        "from_utf8",
        "to_lowercase",
        "to_uppercase",
        "to_ascii_lowercase",
        "trim_start",
        "trim_end",
        "starts_with",
        "ends_with",
        "split_once",
        "rsplit_once",
        "strip_prefix",
        "strip_suffix",
        "contains_key",
        "or_insert",
        "or_default",
        "toString",
        "valueOf",
        "forEach",
        "indexOf",
        "lastIndexOf",
        "startsWith",
        "endsWith",
        "parseInt",
        "parseFloat",
        "isNaN",
        "clearTimeout",
        "clearInterval",
        "Uint8Array",
        "AbortController",
        "URLSearchParams",
        "FormData",
        "Object",
        "Array",
        "Number",
        "Boolean",
        "Error",
        "RegExp",
        "Date",
        "Math",
        "Symbol",
        "BigInt",
        "Buffer",
        "isinstance",
        "issubclass",
        "enumerate",
        "defaultdict",
        "dataclass",
        "staticmethod",
        "classmethod",
        "abstractmethod",
        "getattr",
        "setattr",
        "hasattr",
        "deepcopy",
        "filepath",
        "strconv",
        "serde_json",
        "tokio",
        "tracing",
        "anyhow",
        "thiserror",
    ]
    .into_iter()
    .collect()
});

const BOTANICAL_NOUNS: &[&str] = &[
    "fern",
    "orchid",
    "succulent",
    "bonsai",
    "moss",
    "clover",
    "lavender",
    "bamboo",
    "hibiscus",
    "jasmine",
    "camellia",
    "azalea",
    "magnolia",
    "cypress",
    "maple",
    "lotus",
    "seedling",
    "rootstock",
    "canopy",
    "greenhouse",
    "terrarium",
    "compost",
    "moisture",
    "sunlight",
    "chlorophyll",
    "nectar",
    "pollen",
    "petal",
    "sprout",
    "foliage",
    "meadow",
    "planter",
];

const LIBRARY_NOUNS: &[&str] = &[
    "catalog",
    "manuscript",
    "anthology",
    "codex_leaf",
    "bookmark",
    "periodical",
    "lexicon",
    "index_card",
    "shelf_bay",
    "folio",
    "archive",
    "binding",
    "chapter",
    "preface",
    "colophon",
    "footnote",
    "glossary",
    "scroll",
    "chronicle",
    "almanac",
    "compendium",
    "edition",
    "librarian",
    "carousel",
    "reading_room",
    "monograph",
    "atlas",
    "gazette",
    "pamphlet",
    "parchment",
    "incipit",
    "epilogue",
];

const BAKERY_NOUNS: &[&str] = &[
    "sourdough",
    "croissant",
    "brioche",
    "baguette",
    "ciabatta",
    "focaccia",
    "pretzel",
    "macaron",
    "tartlet",
    "strudel",
    "ganache",
    "meringue",
    "custard",
    "caramel",
    "cinnamon",
    "cardamom",
    "vanilla",
    "yeast_starter",
    "oven_deck",
    "kneading_hook",
    "proofing_tray",
    "flour_sifter",
    "pastry_brush",
    "glaze",
    "crumb_coat",
    "shortbread",
    "muffin_tin",
    "wafer",
    "biscotti",
    "galette",
    "palmier",
    "kouign",
];

/// Prefixes of identifiers produced by Hide-Go itself.
const OWN_TOKEN_PREFIXES: &[&str] = &[
    "HIDE_",
    "__HIDE_",
    "BotanicalSensor",
    "CatalogIndex",
    "OvenController",
    "db_user_",
    "db_pass_placeholder_",
    "app_schema_",
    "user_",
    "dev_member_",
    "svc-node-",
    "sk-sem",
    "CustomConcept_",
    "sym_entity_",
    "git-ref-placeholder-",
];

#[derive(Default)]
struct LayerStats {
    literal: (usize, String, String),
    camouflage: (usize, String, String),
    cipher: (usize, String, String),
}

impl LayerStats {
    fn note(slot: &mut (usize, String, String), original: &str, token: &str) {
        if slot.0 == 0 {
            slot.1 = original.to_string();
            slot.2 = token.to_string();
        }
        slot.0 += 1;
    }
}

pub struct AllHideEngine;

impl AllHideEngine {
    /// Execute All-Hide protection according to traffic category and configured sub-modes.
    ///
    /// Only user content is transformed (message text, tool results, tool arguments); tool
    /// schemas, identifiers, signed reasoning and attachments are forwarded byte-exact so
    /// the request stays a valid API call.
    /// - Chaff: telemetry is acknowledged locally; indexing uploads keep their JSON shape and
    ///   size but every content string is replaced with decoy code.
    /// - Strict literal masking: quoted string literals become `<<HIDE_STR_nnn>>` tokens.
    /// - Isomorphic camouflage: compound code identifiers and `//` comments are mapped into a
    ///   cover domain deterministically from the project salt.
    /// - Cipher garble: each content string becomes a keyed Braille cipher block.
    pub fn process(
        payload: &str,
        category: TrafficCategory,
        config: &HideConfig,
        vault: &PrivacyVault,
    ) -> AllHideOutput {
        Self::process_with_scope(payload, category, config, vault, None)
    }

    pub fn process_with_scope(
        payload: &str,
        category: TrafficCategory,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
    ) -> AllHideOutput {
        if config.all_hide.enable_telemetry_chaff
            && matches!(category, TrafficCategory::Telemetry | TrafficCategory::CodebaseIndexing)
        {
            let chaff = Self::generate_chaff_payload(category, config.all_hide.cover_theme, payload);
            return AllHideOutput {
                vendor_payload: chaff,
                action_taken: "chaff-injected".to_string(),
                findings: vec![LeakFinding {
                    kind: FindingKind::GitMetadata,
                    label: match category {
                        TrafficCategory::Telemetry => "静默遥测已在本地拦截并应答".to_string(),
                        _ => "后台代码索引已替换为同结构诱饵内容".to_string(),
                    },
                    original_preview: format!("Payload ({} bytes)", payload.len()),
                    replacement_token: "<<CHAFF_DECOY_PAYLOAD>>".to_string(),
                    severity: "critical".to_string(),
                    count: 1,
                }],
            };
        }

        let base = SemanticDesensitizer::process_with_scope(payload, config, vault, scope);
        let mut findings = base.findings;
        let mut stats = LayerStats::default();
        let current = base.transformed_payload;

        let trimmed = current.trim();
        let vendor_payload = match serde_json::from_str::<Value>(trimmed)
            .ok()
            .filter(|_| trimmed.starts_with(['{', '[']))
        {
            Some(mut value) => {
                Self::transform_json_content(&mut value, config, vault, scope, &mut stats, 0);
                reserialize_like(trimmed, &value)
            }
            None => Self::transform_text(&current, config, vault, scope, &mut stats),
        };

        let mut actions = Vec::new();
        let ah = &config.all_hide;
        if ah.strict_literal_masking {
            actions.push("strict-literal");
        }
        if ah.enable_isomorphic_camouflage {
            actions.push("all-hide-isomorphic");
        }
        if ah.enable_cipher_garble {
            actions.push("all-hide-cipher");
        }
        let layers = [
            (&stats.literal, "All-Hide 严格字面量掩码", "high"),
            (&stats.camouflage, "同构领域伪装", "high"),
            (&stats.cipher, "All-Hide 密钥流加密乱码", "critical"),
        ];
        for ((count, original, token), label, severity) in layers {
            if *count > 0 {
                let label = if label == "同构领域伪装" {
                    format!("{label} ({:?})", ah.cover_theme)
                } else {
                    label.to_string()
                };
                findings.push(LeakFinding {
                    kind: FindingKind::ProprietaryCodeSymbol,
                    label,
                    original_preview: mask_preview(original),
                    replacement_token: token.chars().take(48).collect(),
                    severity: severity.to_string(),
                    count: *count,
                });
            }
        }

        AllHideOutput {
            vendor_payload,
            action_taken: if actions.is_empty() {
                "desensitized".to_string()
            } else {
                actions.join("+")
            },
            findings,
        }
    }

    /// Walk only content-bearing positions of a request document.
    fn transform_json_content(
        value: &mut Value,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
        stats: &mut LayerStats,
        depth: usize,
    ) {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(s) = value {
                *s = Self::transform_text(s, config, vault, scope, stats);
            }
            return;
        }
        match value {
            Value::Object(map) => {
                if is_opaque_block(map) {
                    return;
                }
                for (key, item) in map.iter_mut() {
                    if is_structural_key(key) || is_schema_key(key) {
                        continue;
                    }
                    Self::transform_json_content(item, config, vault, scope, stats, depth + 1);
                }
            }
            Value::Array(items) => items
                .iter_mut()
                .for_each(|v| Self::transform_json_content(v, config, vault, scope, stats, depth + 1)),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) && depth + 1 < MAX_JSON_DEPTH {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(st) {
                        // Nested tool arguments: transform values, keep the parameter names.
                        Self::transform_json_content(&mut inner, config, vault, scope, stats, depth + 1);
                        *s = reserialize_like(st, &inner);
                        return;
                    }
                }
                *s = Self::transform_text(s, config, vault, scope, stats);
            }
            _ => {}
        }
    }

    fn transform_text(
        text: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
        stats: &mut LayerStats,
    ) -> String {
        if text.trim().is_empty() {
            return text.to_string();
        }
        let ah = &config.all_hide;
        let mut out = text.to_string();
        if ah.strict_literal_masking {
            out = Self::mask_quoted_literals(&out, vault, scope, stats);
        }
        if ah.enable_isomorphic_camouflage {
            out = Self::camouflage(&out, ah.cover_theme, &config.project_salt, vault, scope, stats);
        }
        if ah.enable_cipher_garble {
            let (garbled, _) = Self::apply_cipher_garble_scoped(&out, &config.project_salt, vault, scope);
            LayerStats::note(&mut stats.cipher, &out, &garbled);
            out = garbled;
        }
        out
    }

    /// Mask quoted code string literals with Vault-only tokens (single pass).
    pub fn apply_strict_literal_masking(input: &str, vault: &PrivacyVault) -> (String, Vec<LeakFinding>) {
        let mut stats = LayerStats::default();
        let out = Self::mask_quoted_literals(input, vault, None, &mut stats);
        let findings = (stats.literal.0 > 0)
            .then(|| LeakFinding {
                kind: FindingKind::ProprietaryCodeSymbol,
                label: "All-Hide 严格字面量掩码".to_string(),
                original_preview: mask_preview(&stats.literal.1),
                replacement_token: stats.literal.2.clone(),
                severity: "high".to_string(),
                count: stats.literal.0,
            })
            .into_iter()
            .collect();
        (out, findings)
    }

    fn mask_quoted_literals(text: &str, vault: &PrivacyVault, scope: Option<&str>, stats: &mut LayerStats) -> String {
        let tokens = vault.matcher_for_scope(scope).token_ranges(text);
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in QUOTED_LITERAL_RE.find_iter(text) {
            let lit = m.as_str();
            let inner = &lit[1..lit.len() - 1];
            // Avoid mistaking English contractions (e.g. "don't think it's") for single-quoted string literals.
            if lit.starts_with('\'') {
                let prev_alnum = text[..m.start()]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric());
                let next_alnum = text[m.end()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric());
                if prev_alnum || next_alnum {
                    continue;
                }
            }
            if lit.len() < 4
                || is_placeholder_token(inner)
                || inner.starts_with("<<HIDE_")
                || tokens.iter().any(|&(a, b)| a <= m.start() + 1 && m.end() - 1 <= b)
            {
                continue;
            }
            let quote = &lit[..1];
            let tok = vault.register_derived_scoped_with(
                scope,
                inner,
                "StrictStringLiteral",
                DerivedContext::PlainText,
                |idx| {
                    let tag = vault.keyed_tag("StrictStringLiteral", scope, idx, 8);
                    format!("<<HIDE_STR_{tag}_{idx:03}>>")
                },
            );
            LayerStats::note(&mut stats.literal, inner, &tok);
            out.push_str(&text[last..m.start()]);
            out.push_str(quote);
            out.push_str(&tok);
            out.push_str(quote);
            last = m.end();
        }
        out.push_str(&text[last..]);
        out
    }

    /// Single-pass cover-domain mapping of `//` comments and compound identifiers.
    fn camouflage(
        text: &str,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
        scope: Option<&str>,
        stats: &mut LayerStats,
    ) -> String {
        let tokens = vault.matcher_for_scope(scope).token_ranges(text);
        let overlaps_token = |s: usize, e: usize| tokens.iter().any(|&(a, b)| s < b && a < e);
        let scoped_salt = format!("{salt}:{}", vault.keyed_tag("cover", scope, 0, 12));

        // 1. Comments (`//` and `# `) become numbered cover comments. When a comment contains
        // already-masked tokens (paths, keys, strict literals), camouflage the unmasked prose
        // segments around those tokens instead of skipping the whole comment.
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();
        let cover_phrase = |theme: CoverTheme, n: usize, tag: &str, comment_prefix: &str| {
            let body = match theme {
                CoverTheme::BotanicalGarden => {
                    format!("[BotanicalSensor-{tag}-{n:02}] Calibrate greenhouse soil humidity and mist interval")
                }
                CoverTheme::LibraryCatalog => {
                    format!("[CatalogIndex-{tag}-{n:02}] Verify shelf Dewey decimal classification order")
                }
                CoverTheme::BakeryRecipe => {
                    format!("[OvenController-{tag}-{n:02}] Adjust sourdough fermentation thermal curve")
                }
            };
            format!("{comment_prefix}{body}")
        };
        let mut raw_comments: Vec<(usize, usize)> = LINE_COMMENT_RE
            .captures_iter(text)
            .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end())))
            .collect();
        raw_comments.extend(
            HASH_COMMENT_RE
                .captures_iter(text)
                .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end()))),
        );
        raw_comments.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));

        let mut prev_comment_end = 0usize;
        for (c_start, c_end) in raw_comments {
            if c_start < prev_comment_end {
                continue;
            }
            prev_comment_end = c_end;
            let mut sub_spans: Vec<(usize, usize)> = Vec::new();
            let mut cursor = c_start;
            for &(tok_s, tok_e) in &tokens {
                if tok_e <= c_start || tok_s >= c_end {
                    continue;
                }
                if cursor < tok_s {
                    sub_spans.push((cursor, tok_s));
                }
                cursor = cursor.max(tok_e.min(c_end));
            }
            if cursor < c_end {
                sub_spans.push((cursor, c_end));
            }

            for (s, e) in sub_spans {
                let slice = &text[s..e];
                let lead_ws = slice.len() - slice.trim_start().len();
                let trail_ws = slice.len() - slice.trim_end().len();
                let seg_s = s + lead_ws;
                let seg_e = e.saturating_sub(trail_ws);
                if seg_s >= seg_e {
                    continue;
                }
                let seg = &text[seg_s..seg_e];
                if !seg.chars().any(|c| c.is_alphanumeric()) {
                    continue;
                }
                let n = replacements.len() + 1;
                let tag = vault.keyed_tag("CoverComment", scope, n, 8);
                let comment_prefix = if seg.starts_with("//") {
                    "// "
                } else if seg.starts_with("# ") {
                    "# "
                } else {
                    ""
                };
                let preferred = cover_phrase(theme, n, &tag, comment_prefix);
                let cover =
                    vault.register_derived_scoped_with(scope, seg, "CoverComment", DerivedContext::PlainText, |_| {
                        preferred
                    });
                LayerStats::note(&mut stats.camouflage, seg, &cover);
                replacements.push((seg_s, seg_e, cover));
            }
        }

        // 2. Compound identifiers outside comments and existing tokens.
        let in_comment = |s: usize| replacements.iter().any(|&(a, b, _)| a <= s && s < b);
        let mut covers: HashMap<&str, String> = HashMap::new();
        let mut idents = Vec::new();
        for m in IDENTIFIER_RE.find_iter(text) {
            let ident = m.as_str();
            if in_comment(m.start()) || overlaps_token(m.start(), m.end()) || !is_camouflage_candidate(ident) {
                continue;
            }
            if !covers.contains_key(ident) {
                let preferred = Self::deterministic_cover_symbol(ident, theme, &scoped_salt);
                let cover = vault.register_derived_scoped_with(
                    scope,
                    ident,
                    "IsomorphicSymbol",
                    DerivedContext::PlainText,
                    |_| preferred,
                );
                LayerStats::note(&mut stats.camouflage, ident, &cover);
                covers.insert(ident, cover);
            }
            idents.push((m.start(), m.end(), covers[ident].clone()));
        }
        replacements.extend(idents);
        replacements.sort_by_key(|r| r.0);

        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for (s, e, rep) in replacements {
            if s < last {
                continue;
            }
            out.push_str(&text[last..s]);
            out.push_str(&rep);
            last = e;
        }
        out.push_str(&text[last..]);
        out
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

        // Preserve casing convention (PascalCase / SCREAMING_SNAKE / snake_case).
        if symbol.chars().all(|c| !c.is_lowercase()) {
            format!("{}_{}_{}", w1, w2, suffix).to_uppercase()
        } else if symbol.chars().next().is_some_and(|c| c.is_uppercase()) {
            format!("{}{}{}", capitalize(w1), capitalize(w2), suffix)
        } else if symbol.contains('_') {
            format!("{}_{}_{}", w1, w2, suffix)
        } else {
            format!("{}{}{}", w1.replace('_', ""), capitalize(w2), suffix)
        }
    }

    /// Encrypt text into an authenticated keyed SHA-256 CTR Braille cipher block (`⟦HIDE-CIPHER::...⟧`)
    /// bound to the Vault's 256-bit runtime secret key and `project_salt`.
    pub fn apply_cipher_garble(input: &str, salt: &str, vault: &PrivacyVault) -> (String, Option<LeakFinding>) {
        Self::apply_cipher_garble_scoped(input, salt, vault, None)
    }

    fn apply_cipher_garble_scoped(
        input: &str,
        salt: &str,
        vault: &PrivacyVault,
        scope: Option<&str>,
    ) -> (String, Option<LeakFinding>) {
        if input.trim().is_empty() {
            return (input.to_string(), None);
        }
        let cipher_token =
            vault.register_derived_scoped_with(scope, input, "CipherGarble", DerivedContext::PlainText, |_| {
                Self::encode_keyed_braille_cipher(input, salt, vault)
            });
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

    /// Encrypt UTF-8 bytes using a SHA-256 CTR keystream with a 16-byte random nonce and 16-byte
    /// HMAC-SHA256 authentication tag derived from `vault.secret_key()` + `salt`,
    /// rendered in the Unicode Braille block (U+2800..U+28FF).
    pub fn encode_keyed_braille_cipher(raw: &str, salt: &str, vault: &PrivacyVault) -> String {
        let secret_key = vault.secret_key();
        let nonce = random_cipher_nonce(&secret_key, salt, raw);
        let mut ciphertext = Vec::with_capacity(raw.len());
        let mut ks = Keystream::new(&secret_key, salt, &nonce);
        for &b in raw.as_bytes() {
            ciphertext.push(b ^ ks.next_byte());
        }
        let tag = compute_cipher_tag(&secret_key, salt, &nonce, &ciphertext);

        let mut encoded = String::with_capacity((nonce.len() + ciphertext.len() + 16) * 3 + 32);
        encoded.push_str("⟦HIDE-CIPHER::");
        let to_braille = |b: u8| char::from_u32(0x2800 + b as u32).unwrap_or('⣿');
        nonce.iter().for_each(|&b| encoded.push(to_braille(b)));
        ciphertext.iter().for_each(|&b| encoded.push(to_braille(b)));
        tag.iter().for_each(|&b| encoded.push(to_braille(b)));
        encoded.push('⟧');
        encoded
    }

    /// Decrypt authenticated `⟦HIDE-CIPHER::...⟧` blocks using the local `PrivacyVault` (and `project_salt`).
    /// Unauthenticated, truncated, or tampered blocks are rejected and left untouched.
    pub fn decode_braille_cipher_blocks(text: &str, vault: &PrivacyVault, salt: &str) -> String {
        let prefix = "⟦HIDE-CIPHER::";
        let suffix = "⟧";
        let secret_key = vault.secret_key();
        let mut output = String::with_capacity(text.len());
        let mut rest = text;

        while let Some(start) = rest.find(prefix) {
            output.push_str(&rest[..start]);
            let after_prefix = &rest[start + prefix.len()..];
            let Some(end) = after_prefix.find(suffix) else {
                output.push_str(&rest[start..]);
                return output;
            };
            let full_token = &rest[start..start + prefix.len() + end + suffix.len()];
            if let Some(from_vault) = vault.get_raw_by_token(full_token) {
                output.push_str(&from_vault);
            } else {
                let body = &after_prefix[..end];
                let raw_bytes: Option<Vec<u8>> = body
                    .chars()
                    .map(|ch| (ch as u32).checked_sub(0x2800).filter(|c| *c <= 0xFF).map(|c| c as u8))
                    .collect();
                let decoded = raw_bytes.and_then(|bytes| {
                    // Layout: 16-byte nonce + >=1 byte ciphertext + 16-byte HMAC-SHA256 tag.
                    if bytes.len() <= 32 {
                        return None;
                    }
                    let nonce: [u8; 16] = bytes[..16].try_into().ok()?;
                    let ct_end = bytes.len() - 16;
                    let ciphertext = &bytes[16..ct_end];
                    let tag = &bytes[ct_end..];
                    if !verify_cipher_tag(&secret_key, salt, &nonce, ciphertext, tag) {
                        return None;
                    }
                    let mut ks = Keystream::new(&secret_key, salt, &nonce);
                    String::from_utf8(ciphertext.iter().map(|&cb| cb ^ ks.next_byte()).collect()).ok()
                });
                output.push_str(decoded.as_deref().unwrap_or(full_token));
            }
            rest = &after_prefix[end + suffix.len()..];
        }
        output.push_str(rest);
        output
    }

    /// Decoy payloads. Telemetry gets a local acknowledgement body; indexing uploads keep
    /// their exact JSON shape (keys, numbers, array lengths) and roughly their size, with every
    /// content string swapped for decoy code from the cover theme.
    fn generate_chaff_payload(category: TrafficCategory, theme: CoverTheme, original: &str) -> String {
        if category == TrafficCategory::Telemetry {
            return serde_json::json!({"status": "ok", "accepted": true}).to_string();
        }
        let decoy = match theme {
            CoverTheme::BotanicalGarden => {
                "pub fn check_greenhouse_humidity(sensor_id: u32) -> f32 {\n    // Botanical watering schedule\n    let base = 42.5;\n    base + sensor_id as f32 * 0.1\n}\n"
            }
            CoverTheme::LibraryCatalog => {
                "pub fn lookup_dewey_shelf(book_isbn: &str) -> &'static str {\n    // Public library shelf catalog\n    if book_isbn.is_empty() { \"Shelf-A01\" } else { \"Shelf-B07\" }\n}\n"
            }
            CoverTheme::BakeryRecipe => {
                "pub fn compute_sourdough_hydration(flour_grams: f32) -> f32 {\n    // Artisan bakery recipe calculator\n    flour_grams * 0.75\n}\n"
            }
        };
        let trimmed = original.trim();
        match serde_json::from_str::<Value>(trimmed) {
            Ok(mut value) => {
                let mut n = 0usize;
                decoy_json(&mut value, decoy, &mut n, 0);
                reserialize_like(trimmed, &value)
            }
            Err(_) => decoy_text(decoy, original.chars().count(), 0),
        }
    }
}

fn decoy_json(value: &mut Value, decoy: &str, n: &mut usize, depth: usize) {
    if depth >= MAX_JSON_DEPTH {
        if let Value::String(s) = value {
            *n += 1;
            *s = decoy_text(decoy, s.chars().count(), *n);
        }
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_structural_key(k) {
                    continue;
                }
                if let Value::String(s) = v {
                    if k == "path" || k == "file" || k == "filename" || k.ends_with("_path") {
                        *n += 1;
                        *s = format!("src/garden/module_{:02}.rs", *n);
                        continue;
                    }
                }
                decoy_json(v, decoy, n, depth + 1);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| decoy_json(v, decoy, n, depth + 1)),
        Value::String(s) => {
            *n += 1;
            *s = decoy_text(decoy, s.chars().count(), *n);
        }
        _ => {}
    }
}

fn decoy_text(decoy: &str, len: usize, offset: usize) -> String {
    decoy
        .chars()
        .cycle()
        .skip(offset * 17 % decoy.len())
        .take(len)
        .collect()
}

/// Identifiers worth camouflaging: compound code names (snake_case, camelCase, PascalCase,
/// SCREAMING_SNAKE). Plain words stay readable so prose keeps its meaning.
fn is_camouflage_candidate(ident: &str) -> bool {
    if RESERVED_KEYWORDS.contains(ident) || OWN_TOKEN_PREFIXES.iter().any(|p| ident.starts_with(p)) {
        return false;
    }
    let letters = ident.chars().filter(|c| c.is_alphabetic()).count();
    if letters < 3 {
        return false;
    }
    let snake = ident.trim_matches('_').contains('_');
    let camel = ident
        .as_bytes()
        .windows(2)
        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
    snake || camel
}

fn random_cipher_nonce(secret_key: &[u8; 32], salt: &str, raw: &str) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    if SystemRandom::new().fill(&mut nonce).is_ok() {
        return nonce;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(b"hide-go-nonce-fallback:");
    ctx.update(salt.as_bytes());
    ctx.update(b":");
    ctx.update(raw.as_bytes());
    nonce.copy_from_slice(&ctx.sign().as_ref()[..16]);
    nonce
}

fn cipher_auth_key(secret_key: &[u8; 32], salt: &str) -> hmac::Key {
    let root = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
    let mut sub = hmac::Context::with_key(&root);
    sub.update(b"hide-go-cipher-auth-v3:");
    sub.update(salt.as_bytes());
    hmac::Key::new(hmac::HMAC_SHA256, sub.sign().as_ref())
}

fn compute_cipher_tag(secret_key: &[u8; 32], salt: &str, nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; 16] {
    let key = cipher_auth_key(secret_key, salt);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(nonce);
    ctx.update(&(ciphertext.len() as u64).to_le_bytes());
    ctx.update(ciphertext);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ctx.sign().as_ref()[..16]);
    tag
}

fn verify_cipher_tag(secret_key: &[u8; 32], salt: &str, nonce: &[u8; 16], ciphertext: &[u8], tag: &[u8]) -> bool {
    if tag.len() != 16 {
        return false;
    }
    let expected = compute_cipher_tag(secret_key, salt, nonce, ciphertext);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// SHA-256 CTR keystream: one digest per 32-byte block.
struct Keystream<'a> {
    key: &'a [u8; 32],
    salt: &'a str,
    nonce: &'a [u8; 16],
    block: [u8; 32],
    index: usize,
}

impl<'a> Keystream<'a> {
    fn new(key: &'a [u8; 32], salt: &'a str, nonce: &'a [u8; 16]) -> Self {
        Self {
            key,
            salt,
            nonce,
            block: [0; 32],
            index: 0,
        }
    }

    fn next_byte(&mut self) -> u8 {
        let offset = self.index % 32;
        if offset == 0 {
            let mut hasher = Sha256::new();
            hasher.update(self.key);
            hasher.update(b":hide-go-ctr-v3:");
            hasher.update(self.salt.as_bytes());
            hasher.update(b":");
            hasher.update(self.nonce);
            hasher.update(((self.index / 32) as u64).to_le_bytes());
            self.block.copy_from_slice(&hasher.finalize());
        }
        self.index += 1;
        self.block[offset]
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &chars.as_str().replace('_', ""),
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::PrivacyMode;
    use serde_json::json;

    fn all_hide_cfg() -> HideConfig {
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AllHide;
        cfg.all_hide.enable_cipher_garble = false;
        cfg
    }

    #[test]
    fn protocol_structure_survives_and_prose_stays_readable() {
        let cfg = all_hide_cfg();
        let vault = PrivacyVault::new();
        let body = json!({
            "model": "claude-sonnet-4-5",
            "tools": [{"name": "Read", "description": "Reads a file", "input_schema": {"type": "object",
                "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Please explain why verify_margin_liquidation returns early"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_01A2", "name": "Read",
                    "input": {"file_path": "src/settle_engine.rs"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01A2",
                    "content": "fn verify_margin_liquidation() {} // https://docs.example.com"}]}
            ]
        });
        let out = AllHideEngine::process(&body.to_string(), TrafficCategory::InteractivePrompt, &cfg, &vault);
        let v: Value = serde_json::from_str(&out.vendor_payload).unwrap();
        assert_eq!(v["tools"], body["tools"]);
        assert_eq!(
            v["messages"][1]["content"][0]["id"],
            v["messages"][2]["content"][0]["tool_use_id"]
        );
        assert_eq!(v["messages"][1]["content"][0]["name"], "Read");
        assert!(v["messages"][1]["content"][0]["input"].get("file_path").is_some());
        let text = v["messages"][0]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with("Please explain why ") && !text.contains("verify_margin"),
            "{text}"
        );
        let result = v["messages"][2]["content"][0]["content"].as_str().unwrap();
        assert!(
            !result.contains("verify_margin") && !result.contains("docs.example.com"),
            "{result}"
        );
        assert_eq!(vault.restore_text(&out.vendor_payload).0, body.to_string());
    }

    #[test]
    fn urls_are_not_comments() {
        let cfg = all_hide_cfg();
        let vault = PrivacyVault::new();
        let out = AllHideEngine::process(
            "see https://example.com/a_b for load_config",
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
        );
        assert!(
            out.vendor_payload.starts_with("see https://example.com/"),
            "{}",
            out.vendor_payload
        );
    }

    #[test]
    fn indexing_chaff_keeps_shape_and_size() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.enable_telemetry_chaff = true;
        let vault = PrivacyVault::new();
        let body =
            json!({"model": "text-embedding-3-small", "input": ["fn secret_algo() { titan() }", "x".repeat(300)]});
        let out = AllHideEngine::process(&body.to_string(), TrafficCategory::CodebaseIndexing, &cfg, &vault);
        let v: Value = serde_json::from_str(&out.vendor_payload).unwrap();
        assert_eq!(v["model"], "text-embedding-3-small");
        assert_eq!(v["input"].as_array().unwrap().len(), 2);
        assert_eq!(v["input"][1].as_str().unwrap().chars().count(), 300);
        assert!(!out.vendor_payload.contains("secret_algo"));
    }

    #[test]
    fn cipher_needs_matching_key_and_salt() {
        let vault = PrivacyVault::new();
        let text = "x".repeat(100) + "中文";
        let enc = AllHideEngine::encode_keyed_braille_cipher(&text, "salt", &vault);
        assert_ne!(
            AllHideEngine::decode_braille_cipher_blocks(&enc, &PrivacyVault::new(), "salt"),
            text
        );
        assert_ne!(AllHideEngine::decode_braille_cipher_blocks(&enc, &vault, "wrong"), text);
        assert_eq!(AllHideEngine::decode_braille_cipher_blocks(&enc, &vault, "salt"), text);
    }

    #[test]
    fn cipher_rejects_tampered_blocks() {
        let vault = PrivacyVault::new();
        let text = "secret kernel parameter";
        let enc = AllHideEngine::encode_keyed_braille_cipher(text, "salt", &vault);
        let mut chars: Vec<char> = enc.chars().collect();
        let idx = chars.len() - 2; // inside the trailing 16-byte MAC tag
        chars[idx] = if chars[idx] == '⠀' { '⠁' } else { '⠀' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            AllHideEngine::decode_braille_cipher_blocks(&tampered, &vault, "salt"),
            tampered
        );
    }

    #[test]
    fn comments_with_masked_tokens_still_camouflage_surrounding_prose() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.strict_literal_masking = true;
        let vault = PrivacyVault::new();
        let src =
            "// Proprietary ledger check in /home/alice/secret_repo with \"internal flag\"\npub fn settle_trade() {}";
        let out = AllHideEngine::process(src, TrafficCategory::InteractivePrompt, &cfg, &vault);
        assert!(!out.vendor_payload.contains("Proprietary"), "{}", out.vendor_payload);
        assert!(!out.vendor_payload.contains("ledger"), "{}", out.vendor_payload);
        assert!(!out.vendor_payload.contains("internal flag"), "{}", out.vendor_payload);
        assert!(!out.vendor_payload.contains("/home/alice"), "{}", out.vendor_payload);
        assert!(out.vendor_payload.contains("BotanicalSensor"), "{}", out.vendor_payload);
        assert_eq!(vault.restore_text(&out.vendor_payload).0, src);
    }

    #[test]
    fn hash_comments_and_stdlib_symbols_behave_cleanly() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.strict_literal_masking = false;
        let vault = PrivacyVault::new();
        let src = "#!/usr/bin/env python3\n# Internal proprietary trading loop\n#[derive(Debug)]\ncolor = #1a2b3c\nif isinstance(state, AbortController): serde_json.unwrap_or_else()\ncompute_margin_liquidation()";
        let out = AllHideEngine::process(src, TrafficCategory::InteractivePrompt, &cfg, &vault);
        assert!(out
            .vendor_payload
            .starts_with("#!/usr/bin/env python3\n# [BotanicalSensor-"));
        assert!(!out.vendor_payload.contains("proprietary trading"));
        assert!(out.vendor_payload.contains("#[derive(Debug)]"));
        assert!(out.vendor_payload.contains("#1a2b3c"));
        assert!(out.vendor_payload.contains("isinstance"));
        assert!(out.vendor_payload.contains("AbortController"));
        assert!(out.vendor_payload.contains("serde_json.unwrap_or_else()"));
        assert!(!out.vendor_payload.contains("compute_margin_liquidation"));
        assert_eq!(vault.restore_text(&out.vendor_payload).0, src);
    }
}

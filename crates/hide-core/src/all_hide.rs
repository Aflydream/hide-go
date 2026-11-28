//! Isomorphic code camouflage engine for All-Hide mode.
//!
//! Transforms proprietary identifiers, comments, and business string literals into
//! natural, domain-consistent code from a configurable cover domain while preserving:
//! - exact language syntax, formatting placeholders, imports, and standard library APIs;
//! - wire protocol structure, declared tool schemas, tool names, parameter names, and
//!   harness framing tags (`<USER_REQUEST>`, etc.);
//! - bijective symbol/literal/comment reversibility through `PrivacyVault`, so AI
//!   explanations, diffs, and `edit_file` tool calls restore cleanly onto the local codebase.

use crate::config::{CoverTheme, FindingKind, HideConfig, LeakFinding, TrafficCategory};
use crate::desensitizer::SemanticDesensitizer;
use crate::protocol::{is_opaque_block, is_schema_key, is_structural_key, is_tool_call_object};
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
/// Format placeholders inside string literals (`{}`, `{:?}`, `{0}`, `{name}`, `%s`, `%d`, `%02x`, `${expr}`).
static FORMAT_PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\$\{[^}\r\n]{1,64}\}|\{[A-Za-z0-9_:.?#-]{0,24}\}|%[-+#0 ]?(?:\d+)?(?:\.\d+)?[sdifuxXeEgGvqp%])")
        .unwrap()
});

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
        "BTreeSet",
        "VecDeque",
        "Arc",
        "Mutex",
        "RwLock",
        "Box",
        "Rc",
        "RefCell",
        "Pin",
        "Future",
        "Stream",
        "PathBuf",
        "OsString",
        "Duration",
        "Instant",
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
        "useContext",
        "useReducer",
        "className",
        "onClick",
        "onChange",
        "onSubmit",
        "onKeyDown",
        "innerHTML",
        "textContent",
        "getElementById",
        "addEventListener",
        "removeEventListener",
        "querySelector",
        "querySelectorAll",
        "createElement",
        "preventDefault",
        "stopPropagation",
        "getBoundingClientRect",
        "scrollIntoView",
        "setTimeout",
        "setInterval",
        "localStorage",
        "sessionStorage",
        "encodeURIComponent",
        "decodeURIComponent",
        "readFileSync",
        "writeFileSync",
        "existsSync",
        "mkdirSync",
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
        "is_some",
        "is_none",
        "is_some_and",
        "is_ok",
        "is_err",
        "is_ok_and",
        "into_iter",
        "iter_mut",
        "as_slice",
        "as_bytes",
        "as_mut",
        "to_vec",
        "with_capacity",
        "from_str",
        "from_utf8",
        "from_utf8_lossy",
        "to_lowercase",
        "to_uppercase",
        "to_ascii_lowercase",
        "to_ascii_uppercase",
        "eq_ignore_ascii_case",
        "is_ascii_alphanumeric",
        "is_ascii_alphabetic",
        "is_ascii_digit",
        "trim_start",
        "trim_end",
        "trim_matches",
        "starts_with",
        "ends_with",
        "split_once",
        "rsplit_once",
        "split_whitespace",
        "strip_prefix",
        "strip_suffix",
        "contains_key",
        "or_insert",
        "or_insert_with",
        "or_default",
        "fetch_add",
        "fetch_sub",
        "read_to_string",
        "create_dir_all",
        "insert_str",
        "saturating_add",
        "saturating_sub",
        "saturating_mul",
        "toString",
        "valueOf",
        "toLowerCase",
        "toUpperCase",
        "forEach",
        "indexOf",
        "lastIndexOf",
        "startsWith",
        "endsWith",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isArray",
        "clearTimeout",
        "clearInterval",
        "Uint8Array",
        "AbortController",
        "URLSearchParams",
        "FormData",
        "Headers",
        "Request",
        "Response",
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
        "axum",
        "reqwest",
        "parking_lot",
        "once_cell",
        "StatusCode",
        "HeaderMap",
    ]
    .into_iter()
    .collect()
});

/// Standard library / framework namespace qualifiers whose direct member identifiers stay intact.
const STDLIB_QUALIFIERS: &[&str] = &[
    "std::",
    "core::",
    "alloc::",
    "serde::",
    "serde_json::",
    "tokio::",
    "axum::",
    "reqwest::",
    "tracing::",
    "React.",
    "Object.",
    "Array.",
    "Math.",
    "JSON.",
    "Promise.",
    "Number.",
    "String.",
    "console.",
    "document.",
    "window.",
    "process.",
    "fs.",
    "path.",
    "os.",
    "sys.",
    "fmt.",
    "http.",
    "strings.",
    "strconv.",
    "filepath.",
    "time.",
];

/// Engineering suffixes preserved on PascalCase cover symbols so architectural roles stay clear.
const PRESERVED_TYPE_SUFFIXES: &[&str] = &[
    "Controller",
    "Repository",
    "Middleware",
    "Serializer",
    "Validator",
    "Scheduler",
    "Dispatcher",
    "Collector",
    "Extractor",
    "Connector",
    "Processor",
    "Formatter",
    "Provider",
    "Listener",
    "Registry",
    "Response",
    "Resolver",
    "Iterator",
    "Metadata",
    "Settings",
    "Snapshot",
    "Protocol",
    "Envelope",
    "Service",
    "Manager",
    "Handler",
    "Builder",
    "Factory",
    "Session",
    "Context",
    "Request",
    "Options",
    "Summary",
    "Channel",
    "Storage",
    "Scanner",
    "Matcher",
    "Adapter",
    "Wrapper",
    "Monitor",
    "Metrics",
    "Client",
    "Server",
    "Engine",
    "Config",
    "Schema",
    "Policy",
    "Filter",
    "Router",
    "Worker",
    "Stream",
    "Buffer",
    "Record",
    "Result",
    "Report",
    "Status",
    "Signal",
    "Params",
    "Helper",
    "Loader",
    "Parser",
    "Writer",
    "Reader",
    "Error",
    "State",
    "Store",
    "Cache",
    "Queue",
    "Stack",
    "Index",
    "Entry",
    "Event",
    "Token",
    "Frame",
    "Guard",
    "Scope",
    "Layer",
    "Table",
    "Query",
    "Input",
    "Model",
    "Pool",
    "Node",
    "Item",
    "Spec",
    "Rule",
    "Kind",
    "Mode",
    "Type",
    "Info",
    "Meta",
    "View",
    "List",
    "Map",
    "Set",
    "Key",
    "Id",
];

/// Function / method verb prefixes mapped to authentic domain actions.
const CODE_VERB_PREFIXES: &[&str] = &[
    "calculate",
    "compute",
    "validate",
    "verify",
    "execute",
    "process",
    "resolve",
    "extract",
    "collect",
    "convert",
    "refresh",
    "reconcile",
    "register",
    "dispatch",
    "schedule",
    "evaluate",
    "analyze",
    "inspect",
    "classify",
    "serialize",
    "deserialize",
    "transform",
    "sanitize",
    "restore",
    "encrypt",
    "decrypt",
    "generate",
    "publish",
    "subscribe",
    "initialize",
    "configure",
    "handle",
    "create",
    "update",
    "delete",
    "remove",
    "insert",
    "append",
    "format",
    "render",
    "detect",
    "filter",
    "search",
    "lookup",
    "record",
    "report",
    "submit",
    "encode",
    "decode",
    "parse",
    "build",
    "check",
    "fetch",
    "write",
    "close",
    "start",
    "flush",
    "merge",
    "split",
    "count",
    "apply",
    "match",
    "reset",
    "clear",
    "clean",
    "query",
    "load",
    "save",
    "send",
    "sync",
    "read",
    "find",
    "list",
    "make",
    "init",
    "open",
    "stop",
    "emit",
    "push",
    "pull",
    "scan",
    "sign",
    "sort",
    "trim",
    "wrap",
    "get",
    "set",
    "add",
    "put",
    "run",
    "map",
    "is",
    "has",
    "can",
    "should",
    "on",
];

const CONST_PREFIXES: &[&str] = &["MAX_", "MIN_", "DEFAULT_", "ENABLE_", "IS_", "NUM_", "HTTP_", "ERR_"];

struct ThemeLexicon {
    adjectives: &'static [&'static str],
    nouns: &'static [&'static str],
    parts: &'static [&'static str],
    verbs: &'static [&'static str],
    comment_actions: &'static [&'static str],
    comment_subjects: &'static [&'static str],
    comment_contexts: &'static [&'static str],
    literal_subjects: &'static [&'static str],
    literal_states: &'static [&'static str],
    chaff_modules: &'static [(&'static str, &'static str)],
}

const BOTANICAL_LEXICON: ThemeLexicon = ThemeLexicon {
    adjectives: &[
        "north", "south", "ambient", "nocturnal", "canopy", "subsoil", "drip", "misting", "shaded", "alpine", "humid",
        "seasonal", "basal", "foliar", "mineral", "vernal",
    ],
    nouns: &[
        "greenhouse", "seedling", "rootstock", "moisture", "canopy", "terrarium", "planter", "trellis", "louver",
        "reservoir", "manifold", "substrate", "chlorophyll", "foliage", "nursery", "orchard", "irrigation", "humidity",
        "sunlight", "compost", "drainage", "propagation", "greenbed", "airflow",
    ],
    parts: &[
        "bay", "zone", "tray", "valve", "probe", "line", "bed", "cycle", "level", "rate", "span", "index", "limit",
        "offset", "reading", "threshold", "schedule", "curve", "ratio", "window",
    ],
    verbs: &[
        "calibrate", "measure", "sample", "adjust", "balance", "flush", "mist", "schedule", "inspect", "verify",
        "record", "sync", "clamp", "prune", "track", "poll", "compute", "update", "check", "refresh",
    ],
    comment_actions: &[
        "Calibrate", "Verify", "Clamp", "Adjust", "Balance", "Flush", "Sample", "Record", "Sync", "Check",
        "Recompute", "Normalize", "Inspect", "Schedule", "Track", "Reset",
    ],
    comment_subjects: &[
        "soil moisture baseline",
        "misting manifold pressure",
        "canopy airflow velocity",
        "vent louver angle",
        "substrate conductivity reading",
        "dawn irrigation schedule",
        "seedling tray humidity",
        "shade cloth duty cycle",
        "nutrient dosing ratio",
        "reservoir return temperature",
        "rootstock drainage flow",
        "grow-light photoperiod curve",
        "ambient dew point drift",
        "propagation bay thermostat",
    ],
    comment_contexts: &[
        "before sunrise cycle",
        "across north bay benches",
        "after peak irradiance",
        "during recirculation pass",
        "to prevent leaf condensation",
        "ahead of morning misting",
        "following mineral flush",
        "within seasonal bounds",
        "for dormant tray group",
        "along perimeter drip line",
        "prior to valve switchover",
        "under low-light fallback",
    ],
    literal_subjects: &[
        "north bay moisture",
        "drip manifold pressure",
        "canopy humidity",
        "louver vent angle",
        "seedling tray temperature",
        "reservoir pH balance",
        "shade cloth relay",
        "substrate conductivity",
        "irrigation schedule",
        "greenhouse airflow",
    ],
    literal_states: &[
        "threshold exceeded",
        "calibration complete",
        "reading out of range",
        "cycle synchronized",
        "baseline updated",
        "schedule deferred",
        "sensor standby",
        "flush required",
    ],
    chaff_modules: &[
        (
            "src/sensors/moisture_probe.rs",
            "pub struct MoistureSample {\n    pub bay_id: u16,\n    pub volumetric_pct: f32,\n    pub temp_c: f32,\n}\n\npub fn normalize_probe_reading(raw_mv: u16, temp_c: f32) -> f32 {\n    let compensated = raw_mv as f32 * (1.0 + (temp_c - 20.0) * 0.002);\n    (compensated / 3300.0 * 100.0).clamp(0.0, 100.0)\n}\n",
        ),
        (
            "src/irrigation/valve_scheduler.rs",
            "pub struct DripZone {\n    pub zone_index: usize,\n    pub target_pct: f32,\n    pub max_seconds: u32,\n}\n\npub fn compute_pulse_duration(zone: &DripZone, current_pct: f32) -> u32 {\n    if current_pct >= zone.target_pct {\n        return 0;\n    }\n    let deficit = (zone.target_pct - current_pct).min(30.0);\n    ((deficit / 30.0) * zone.max_seconds as f32).round() as u32\n}\n",
        ),
        (
            "src/climate/louver_control.rs",
            "pub fn target_louver_angle(ambient_c: f32, setpoint_c: f32, wind_kph: f32) -> u8 {\n    if wind_kph > 45.0 {\n        return 10;\n    }\n    let delta = (ambient_c - setpoint_c).max(0.0);\n    ((delta * 12.0).round() as u8).min(90)\n}\n",
        ),
    ],
};

const LIBRARY_LEXICON: ThemeLexicon = ThemeLexicon {
    adjectives: &[
        "archival", "mezzanine", "serial", "bound", "rare", "reference", "annotated", "folio", "circulating",
        "regional", "cataloged", "indexed", "curated", "quarterly", "microfilm", "interlibrary",
    ],
    nouns: &[
        "catalog", "manuscript", "anthology", "periodical", "lexicon", "folio", "archive", "binding", "chapter",
        "colophon", "footnote", "glossary", "chronicle", "almanac", "edition", "monograph", "gazette", "parchment",
        "vellum", "quarto", "appendix", "concordance", "callnumber", "ledger",
    ],
    parts: &[
        "shelf", "stack", "aisle", "batch", "slip", "stamp", "label", "record", "index", "entry", "queue", "slot",
        "range", "count", "checksum", "heading", "branch", "manifest", "hold", "loan",
    ],
    verbs: &[
        "catalog", "reindex", "reconcile", "validate", "normalize", "audit", "sort", "shelve", "archive", "verify",
        "inspect", "consolidate", "lookup", "refresh", "route", "scan", "check", "update", "record", "bind",
    ],
    comment_actions: &[
        "Verify", "Reconcile", "Reindex", "Normalize", "Audit", "Consolidate", "Refresh", "Validate", "Inspect",
        "Update", "Check", "Sort", "Archive", "Route", "Scan", "Trim",
    ],
    comment_subjects: &[
        "call-number shelf order",
        "barcode scan batch",
        "monograph subject headings",
        "interlibrary routing manifest",
        "transliterated author diacritics",
        "incoming serial ISSN checksums",
        "reading-room hold queue",
        "duplicate authority entries",
        "rare folio vault climate log",
        "spine-label printer alignment",
        "microfilm frame calibration",
        "circulation return ledger",
        "periodical binding schedule",
        "archival box barcode index",
    ],
    comment_contexts: &[
        "across mezzanine stacks",
        "after morning acquisition",
        "before branch dispatch",
        "within quarterly audit",
        "for overdue hold shelves",
        "prior to catalog export",
        "along west reading wing",
        "during overnight reindex",
        "from regional loan desk",
        "under strict MARC rules",
        "after scanner warm-up",
        "for reserve collection",
    ],
    literal_subjects: &[
        "shelf call-number",
        "circulation ledger",
        "authority heading",
        "ISSN checksum",
        "interlibrary manifest",
        "hold shelf slot",
        "folio archive box",
        "barcode scan batch",
        "periodical binding",
        "catalog index",
    ],
    literal_states: &[
        "mismatch detected",
        "reconciliation complete",
        "entry archived",
        "batch synchronized",
        "shelf updated",
        "hold expired",
        "index pending",
        "verification passed",
    ],
    chaff_modules: &[
        (
            "src/catalog/call_number.rs",
            "pub struct CallNumber {\n    pub class_code: String,\n    pub cutter: String,\n    pub year: u16,\n}\n\npub fn normalize_cutter(raw: &str) -> String {\n    raw.trim().to_ascii_uppercase().replace(' ', \"\")\n}\n",
        ),
        (
            "src/circulation/hold_queue.rs",
            "pub fn days_until_expiry(hold_days: u16, elapsed: u16) -> u16 {\n    hold_days.saturating_sub(elapsed)\n}\n",
        ),
        (
            "src/archive/checksum.rs",
            "pub fn verify_issn_digits(digits: &[u8; 8]) -> bool {\n    let sum: u32 = digits.iter().enumerate().map(|(i, &d)| (8 - i as u32) * d as u32).sum();\n    sum % 11 == 0\n}\n",
        ),
    ],
};

const BAKERY_LEXICON: ThemeLexicon = ThemeLexicon {
    adjectives: &[
        "hearth", "overnight", "artisan", "deck", "ambient", "fermented", "laminated", "seeded", "golden", "chilled",
        "stoneground", "folded", "sifted", "warmed", "tempered", "proofed",
    ],
    nouns: &[
        "sourdough", "croissant", "brioche", "baguette", "ciabatta", "focaccia", "pretzel", "macaron", "tartlet",
        "strudel", "ganache", "meringue", "custard", "caramel", "cinnamon", "starter", "oven", "proofer", "sifter",
        "pastry", "glaze", "crumb", "levain", "boule",
    ],
    parts: &[
        "rack", "deck", "tray", "batch", "fold", "cycle", "temp", "steam", "timer", "ratio", "weight", "hydration",
        "stage", "crust", "probe", "setpoint", "window", "margin", "schedule", "level",
    ],
    verbs: &[
        "temper", "proof", "knead", "laminate", "sift", "fold", "steam", "rotate", "weigh", "bake", "cool", "glaze",
        "calibrate", "measure", "monitor", "verify", "adjust", "check", "log", "balance",
    ],
    comment_actions: &[
        "Check", "Calibrate", "Adjust", "Verify", "Record", "Weigh", "Rotate", "Inspect", "Log", "Stabilize",
        "Monitor", "Clamp", "Balance", "Reset", "Sync", "Measure",
    ],
    comment_subjects: &[
        "bulk fermentation dough temperature",
        "deck steam injection duration",
        "proofer humidity setpoint",
        "butter plasticity curve",
        "hearth stone heat-soak timer",
        "starter refreshment ratio",
        "baking rack rotation interval",
        "custard tempering probe",
        "flour hopper sift screen",
        "ambient kitchen dew point",
        "meringue whip speed profile",
        "cooling rack glaze interval",
        "levain hydration percentage",
        "oven spring vent damper",
    ],
    comment_contexts: &[
        "before first coil fold",
        "for morning boule batch",
        "during overnight cold proof",
        "ahead of pastry sheeting",
        "after hearth preheat",
        "halfway through caramelization",
        "against ice-bath reference",
        "prior to ganache pour",
        "within artisan bakery spec",
        "on upper deck stone",
        "before scoring pass",
        "under humid summer load",
    ],
    literal_subjects: &[
        "deck oven steam",
        "proofer humidity",
        "levain hydration",
        "dough fermentation temp",
        "butter lamination fold",
        "hearth preheat timer",
        "custard probe reading",
        "starter batch weight",
        "cooling rack schedule",
        "pastry glaze cycle",
    ],
    literal_states: &[
        "setpoint reached",
        "temperature out of range",
        "calibration complete",
        "rotation required",
        "batch synchronized",
        "timer deferred",
        "probe standby",
        "cycle verified",
    ],
    chaff_modules: &[
        (
            "src/dough/hydration.rs",
            "pub struct DoughFormula {\n    pub flour_grams: f32,\n    pub water_grams: f32,\n    pub starter_grams: f32,\n}\n\npub fn effective_hydration_pct(f: &DoughFormula) -> f32 {\n    let total_flour = f.flour_grams + f.starter_grams * 0.5;\n    let total_water = f.water_grams + f.starter_grams * 0.5;\n    if total_flour <= 0.0 { 0.0 } else { (total_water / total_flour) * 100.0 }\n}\n",
        ),
        (
            "src/oven/steam_cycle.rs",
            "pub fn steam_seconds_for_weight(loaf_grams: u32) -> u32 {\n    ((loaf_grams / 150) + 4).clamp(4, 18)\n}\n",
        ),
        (
            "src/proofing/schedule.rs",
            "pub fn estimate_proof_minutes(ambient_c: f32, base_minutes: u32) -> u32 {\n    let factor = 2.0_f32.powf((24.0 - ambient_c) / 8.0);\n    ((base_minutes as f32) * factor).round().clamp(30.0, 960.0) as u32\n}\n",
        ),
    ],
};

fn lexicon_for(theme: CoverTheme) -> &'static ThemeLexicon {
    match theme {
        CoverTheme::BotanicalGarden => &BOTANICAL_LEXICON,
        CoverTheme::LibraryCatalog => &LIBRARY_LEXICON,
        CoverTheme::BakeryRecipe => &BAKERY_LEXICON,
    }
}

/// Prefixes of synthetic placeholder forms excluded from identifier camouflage.
const OWN_TOKEN_PREFIXES: &[&str] = &[
    "HIDE_",
    "__HIDE_",
    "key_ref_",
    "sec_",
    "tok_",
    "ref_",
    "sym_",
    "BotanicalSensor",
    "CatalogIndex",
    "OvenController",
    "db_user_",
    "db_pass_placeholder_",
    "app_schema_",
    "dev_member_",
    "svc-node-",
    "sk-sem",
    "CustomConcept_",
    "sym_entity_",
    "git-ref-placeholder-",
];

/// Syntax/runtime strings that must stay literal so code remains compilable and editable.
const PRESERVED_LITERALS: &[&str] = &[
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "CONNECT",
    "utf-8",
    "UTF-8",
    "utf8",
    "ascii",
    "latin1",
    "base64",
    "hex",
    "binary",
    "application/json",
    "text/plain",
    "text/html",
    "text/event-stream",
    "application/octet-stream",
    "multipart/form-data",
    "application/x-www-form-urlencoded",
    "Content-Type",
    "Authorization",
    "Accept",
    "User-Agent",
    "Cache-Control",
    "no-cache",
    "no-store",
    "Bearer",
    "Basic",
    "true",
    "false",
    "null",
    "none",
    "undefined",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "http",
    "https",
    "ws",
    "wss",
    "use strict",
    "use client",
    "use server",
    "__main__",
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
                // Dynamically collect declared tool names and parameter names from this request's
                // own schema so All-Hide never breaks harness tool invocation or file-edit calls.
                let mut protected = HashSet::new();
                collect_declared_schema_identifiers(&value, &mut protected, 0);
                Self::transform_json_content(&mut value, config, vault, scope, &protected, &mut stats, 0);
                reserialize_like(trimmed, &value)
            }
            None => {
                let protected = HashSet::new();
                Self::transform_text(&current, config, vault, scope, &protected, &mut stats)
            }
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
    #[allow(clippy::too_many_arguments)]
    fn transform_json_content(
        value: &mut Value,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
        protected: &HashSet<String>,
        stats: &mut LayerStats,
        depth: usize,
    ) {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(s) = value {
                *s = Self::transform_text(s, config, vault, scope, protected, stats);
            }
            return;
        }
        match value {
            Value::Object(map) => {
                if is_opaque_block(map) {
                    return;
                }
                // Preserve harness system/developer prompt messages (secrets/paths were already
                // masked by SemanticDesensitizer before All-Hide runs).
                if matches!(map.get("role").and_then(Value::as_str), Some("system" | "developer")) {
                    return;
                }
                let tool_call = is_tool_call_object(map);
                for (key, item) in map.iter_mut() {
                    // Preserve protocol schema, tool names, and harness system instructions
                    // (secrets/paths inside system instructions were already scrubbed by SemanticDesensitizer).
                    if is_structural_key(key)
                        || is_schema_key(key)
                        || matches!(
                            key.as_str(),
                            "system" | "systemInstruction" | "system_instruction" | "instructions"
                        )
                        || (tool_call && key == "name")
                    {
                        continue;
                    }
                    Self::transform_json_content(item, config, vault, scope, protected, stats, depth + 1);
                }
            }
            Value::Array(items) => items
                .iter_mut()
                .for_each(|v| Self::transform_json_content(v, config, vault, scope, protected, stats, depth + 1)),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) && depth + 1 < MAX_JSON_DEPTH {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(st) {
                        // Nested tool arguments: transform values, keep the parameter names.
                        Self::transform_json_content(&mut inner, config, vault, scope, protected, stats, depth + 1);
                        *s = reserialize_like(st, &inner);
                        return;
                    }
                }
                *s = Self::transform_text(s, config, vault, scope, protected, stats);
            }
            _ => {}
        }
    }

    fn transform_text(
        text: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
        protected: &HashSet<String>,
        stats: &mut LayerStats,
    ) -> String {
        if text.trim().is_empty() {
            return text.to_string();
        }
        let ah = &config.all_hide;
        let mut out = text.to_string();
        if ah.strict_literal_masking {
            out = Self::mask_quoted_literals(
                &out,
                ah.cover_theme,
                &config.project_salt,
                vault,
                scope,
                protected,
                stats,
            );
        }
        if ah.enable_isomorphic_camouflage {
            out = Self::camouflage(
                &out,
                ah.cover_theme,
                &config.project_salt,
                vault,
                scope,
                protected,
                stats,
            );
        }
        if ah.enable_cipher_garble {
            let (garbled, _) = Self::apply_cipher_garble_scoped(&out, &config.project_salt, vault, scope);
            LayerStats::note(&mut stats.cipher, &out, &garbled);
            out = garbled;
        }
        out
    }

    /// Mask domain-specific quoted string literals with natural cover strings (preserving format
    /// placeholders and skipping imports, MIME types, HTTP methods, and file paths).
    pub fn apply_strict_literal_masking(input: &str, vault: &PrivacyVault) -> (String, Vec<LeakFinding>) {
        let mut stats = LayerStats::default();
        let protected = HashSet::new();
        let out = Self::mask_quoted_literals(
            input,
            CoverTheme::BotanicalGarden,
            "",
            vault,
            None,
            &protected,
            &mut stats,
        );
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

    fn mask_quoted_literals(
        text: &str,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
        scope: Option<&str>,
        protected: &HashSet<String>,
        stats: &mut LayerStats,
    ) -> String {
        if !text.contains('"') && !text.contains('\'') {
            return text.to_string();
        }
        let tokens = vault.matcher_for_scope(scope).token_ranges(text);
        let mut raw_comments: Vec<(usize, usize)> = if text.contains("//") {
            LINE_COMMENT_RE
                .captures_iter(text)
                .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end())))
                .collect()
        } else {
            Vec::new()
        };
        if text.contains('#') {
            raw_comments.extend(
                HASH_COMMENT_RE
                    .captures_iter(text)
                    .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end()))),
            );
        }
        raw_comments.sort_unstable();
        let mut comment_ranges: Vec<(usize, usize)> = Vec::with_capacity(raw_comments.len());
        for (cs, ce) in raw_comments {
            if let Some(last) = comment_ranges.last_mut() {
                if cs <= last.1 {
                    last.1 = last.1.max(ce);
                    continue;
                }
            }
            comment_ranges.push((cs, ce));
        }
        let lex = lexicon_for(theme);
        let mut out = String::with_capacity(text.len());
        let mut last = 0;

        for m in QUOTED_LITERAL_RE.find_iter(text) {
            let c_idx = comment_ranges.partition_point(|&(cs, _)| cs <= m.start());
            if c_idx > 0 && comment_ranges[c_idx - 1].1 >= m.end() {
                continue;
            }
            let lit = m.as_str();
            let inner = &lit[1..lit.len() - 1];
            // Avoid mistaking English contractions (e.g. "don't think it's") for single-quoted literals.
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
            let t_idx = tokens.partition_point(|&(a, _)| a <= m.start() + 1);
            let inside_token = t_idx > 0 && tokens[t_idx - 1].1 >= m.end() - 1;
            if should_preserve_quoted_literal(text, m.start(), inner, protected)
                || is_placeholder_token(inner)
                || inner.starts_with("<<HIDE_")
                || inside_token
            {
                continue;
            }
            let quote = &lit[..1];
            let placeholders: Vec<&str> = FORMAT_PLACEHOLDER_RE.find_iter(inner).map(|pm| pm.as_str()).collect();
            let (cover, _) = vault.register_derived_scoped_unique(
                scope,
                inner,
                "StrictStringLiteral",
                DerivedContext::PlainText,
                |attempt| {
                    let d = vault.keyed_bytes("cover-literal", scope, salt, inner, attempt);
                    format_natural_cover_literal(inner, &placeholders, lex, &d, attempt)
                },
            );
            LayerStats::note(&mut stats.literal, inner, &cover);
            out.push_str(&text[last..m.start()]);
            out.push_str(quote);
            out.push_str(&cover);
            out.push_str(quote);
            last = m.end();
        }
        out.push_str(&text[last..]);
        out
    }

    /// Single-pass cover-domain mapping of `//` / `# ` comments and compound identifiers.
    #[allow(clippy::too_many_arguments)]
    fn camouflage(
        text: &str,
        theme: CoverTheme,
        salt: &str,
        vault: &PrivacyVault,
        scope: Option<&str>,
        protected: &HashSet<String>,
        stats: &mut LayerStats,
    ) -> String {
        let tokens = vault.matcher_for_scope(scope).token_ranges(text);
        // `tokens` is sorted non-overlapping; binary search makes overlap lookup O(log T).
        let overlaps_token = |s: usize, e: usize| {
            let idx = tokens.partition_point(|&(a, _)| a < e);
            idx > 0 && tokens[idx - 1].1 > s
        };
        let lex = lexicon_for(theme);

        // 1. Comments (`//` and `# `) become natural domain-authentic comments (no synthetic tags).
        let mut replacements: Vec<(usize, usize, String)> = Vec::new();
        let mut raw_comments: Vec<(usize, usize)> = if text.contains("//") {
            LINE_COMMENT_RE
                .captures_iter(text)
                .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end())))
                .collect()
        } else {
            Vec::new()
        };
        if text.contains('#') {
            raw_comments.extend(
                HASH_COMMENT_RE
                    .captures_iter(text)
                    .filter_map(|caps| caps.get(1).map(|m| (m.start(), m.end()))),
            );
        }
        raw_comments.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));

        let mut prev_comment_end = 0usize;
        for (c_start, c_end) in raw_comments {
            if c_start < prev_comment_end {
                continue;
            }
            prev_comment_end = c_end;
            let mut sub_spans: Vec<(usize, usize)> = Vec::new();
            let mut cursor = c_start;
            let first_tok = tokens.partition_point(|&(_, tok_e)| tok_e <= c_start);
            for &(tok_s, tok_e) in &tokens[first_tok..] {
                if tok_s >= c_end {
                    break;
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
                let comment_prefix = if seg.starts_with("//") {
                    "// "
                } else if seg.starts_with("# ") {
                    "# "
                } else {
                    ""
                };
                // Keep clean non-alphanumeric boundaries when a comment segment touches an existing
                // vault token (e.g. `/opt/work/a1b2c3d4` immediately followed by `/repo`), so
                // `Matcher::restore` sees valid word boundaries on both sides.
                let needs_lead_sep = comment_prefix.is_empty()
                    && seg_s > c_start
                    && text
                        .as_bytes()
                        .get(seg_s.saturating_sub(1))
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
                let needs_trail_sep = seg_e < c_end
                    && text
                        .as_bytes()
                        .get(seg_e)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
                let (cover, _) = vault.register_derived_scoped_unique(
                    scope,
                    seg,
                    "CoverComment",
                    DerivedContext::PlainText,
                    |attempt| {
                        let d = vault.keyed_bytes("cover-comment", scope, salt, seg, attempt);
                        let mut c = format_natural_comment(comment_prefix, lex, &d, attempt);
                        if needs_lead_sep {
                            c.insert(0, ' ');
                        }
                        if needs_trail_sep {
                            c.push(' ');
                        }
                        c
                    },
                );
                LayerStats::note(&mut stats.camouflage, seg, &cover);
                replacements.push((seg_s, seg_e, cover));
            }
        }

        // 2. Compound identifiers outside comments, XML tags, stdlib namespaces, and existing tokens.
        // `replacements` holds non-overlapping sorted comment spans; binary search is O(log C).
        let in_comment = |s: usize| {
            let idx = replacements.partition_point(|&(a, _, _)| a <= s);
            idx > 0 && s < replacements[idx - 1].1
        };
        let mut covers: HashMap<&str, String> = HashMap::new();
        let mut idents = Vec::new();
        for m in IDENTIFIER_RE.find_iter(text) {
            let ident = m.as_str();
            if in_comment(m.start())
                || overlaps_token(m.start(), m.end())
                || protected.contains(ident)
                || !is_camouflage_candidate(ident)
                || is_protected_lexical_context(text, m.start(), m.end())
            {
                continue;
            }
            if !covers.contains_key(ident) {
                let (cover, _) = vault.register_derived_scoped_unique(
                    scope,
                    ident,
                    "IsomorphicSymbol",
                    DerivedContext::PlainText,
                    |attempt| {
                        let d = vault.keyed_bytes("cover-ident", scope, salt, ident, attempt);
                        format_cover_symbol_from_digest(ident, theme, &d, attempt)
                    },
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
        let digest: [u8; 32] = hasher.finalize().into();
        format_cover_symbol_from_digest(symbol, theme, &digest, 0)
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

    /// Multi-module realistic decoy payloads for telemetry / background indexing uploads.
    fn generate_chaff_payload(category: TrafficCategory, theme: CoverTheme, original: &str) -> String {
        if category == TrafficCategory::Telemetry {
            return serde_json::json!({"status": "ok", "accepted": true}).to_string();
        }
        let modules = lexicon_for(theme).chaff_modules;
        let trimmed = original.trim();
        match serde_json::from_str::<Value>(trimmed) {
            Ok(mut value) => {
                let mut n = 0usize;
                decoy_json(&mut value, modules, &mut n, 0);
                reserialize_like(trimmed, &value)
            }
            Err(_) => decoy_module_text(modules, original.chars().count(), 0),
        }
    }
}

/// Dynamically collect tool names and parameter property names declared in the request schema.
fn collect_declared_schema_identifiers(value: &Value, out: &mut HashSet<String>, depth: usize) {
    if depth >= 10 {
        return;
    }
    match value {
        Value::Object(map) => {
            for container in ["tools", "functions", "functionDeclarations", "function_declarations"] {
                if let Some(arr) = map.get(container).and_then(Value::as_array) {
                    for tool in arr {
                        collect_tool_def_identifiers(tool, out, 0);
                    }
                }
            }
            for (k, v) in map {
                if !matches!(
                    k.as_str(),
                    "tools" | "functions" | "functionDeclarations" | "function_declarations"
                ) && (v.is_object() || v.is_array())
                {
                    collect_declared_schema_identifiers(v, out, depth + 1);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter().take(64) {
                if item.is_object() {
                    collect_declared_schema_identifiers(item, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn collect_tool_def_identifiers(val: &Value, out: &mut HashSet<String>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Some(map) = val.as_object() else { return };
    if let Some(name) = map.get("name").and_then(Value::as_str) {
        if !name.is_empty() {
            out.insert(name.to_string());
        }
    }
    if let Some(func) = map.get("function") {
        collect_tool_def_identifiers(func, out, depth + 1);
    }
    if let Some(props) = map.get("properties").and_then(Value::as_object) {
        for (prop_name, prop_schema) in props {
            out.insert(prop_name.clone());
            collect_tool_def_identifiers(prop_schema, out, depth + 1);
        }
    }
    for sub in ["parameters", "input_schema", "parametersJsonSchema", "items"] {
        if let Some(child) = map.get(sub) {
            collect_tool_def_identifiers(child, out, depth + 1);
        }
    }
}

/// Decide whether a quoted string literal is syntax/runtime-critical and should stay untouched.
fn should_preserve_quoted_literal(text: &str, quote_start: usize, inner: &str, protected: &HashSet<String>) -> bool {
    let trimmed = inner.trim();
    if trimmed.len() < 2 || PRESERVED_LITERALS.contains(&trimmed) || protected.contains(trimmed) {
        return true;
    }
    // Pure whitespace, punctuation, numbers, or format-only placeholders (e.g. "{}", "%s")
    if !trimmed.chars().any(|c| c.is_alphabetic()) {
        return true;
    }
    let stripped_fmt = FORMAT_PLACEHOLDER_RE.replace_all(trimmed, "");
    if !stripped_fmt.chars().any(|c| c.is_alphabetic()) {
        return true;
    }
    // Single short lowercase technical key/tag (e.g. "id", "json", "error", "data", "text")
    if trimmed.len() <= 14
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !trimmed.contains('_')
    {
        return true;
    }
    // File paths / relative module specifiers / URLs (keep structure intact for edits & imports)
    if trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("@/")
        || trimmed.starts_with('@')
        || trimmed.contains("://")
        || matches!(
            trimmed.rsplit_once('.').map(|(_, ext)| ext),
            Some(
                "rs" | "ts"
                    | "tsx"
                    | "js"
                    | "jsx"
                    | "py"
                    | "go"
                    | "json"
                    | "toml"
                    | "yaml"
                    | "yml"
                    | "css"
                    | "html"
                    | "md"
            )
        )
    {
        return true;
    }
    // Module import / export / require statements on the current line
    let line_start = text[..quote_start].rfind('\n').map_or(0, |i| i + 1);
    let prefix_on_line = text[line_start..quote_start].trim_start();
    if prefix_on_line.starts_with("import ")
        || prefix_on_line.starts_with("export ")
        || prefix_on_line.ends_with("from ")
        || prefix_on_line.ends_with("require(")
        || prefix_on_line.ends_with("include!(")
        || prefix_on_line.ends_with("include_str!(")
        || prefix_on_line.ends_with("include_bytes!(")
    {
        return true;
    }
    false
}

/// Build a natural, domain-consistent cover string literal preserving any format placeholders.
fn format_natural_cover_literal(
    original: &str,
    placeholders: &[&str],
    lex: &ThemeLexicon,
    digest: &[u8; 32],
    attempt: usize,
) -> String {
    let subj = lex.literal_subjects[(digest[0] as usize + attempt) % lex.literal_subjects.len()];
    let state =
        lex.literal_states[(digest[1] as usize + attempt / lex.literal_subjects.len()) % lex.literal_states.len()];
    let adj = lex.adjectives[(digest[2] as usize + attempt) % lex.adjectives.len()];
    let part = lex.parts[(digest[3] as usize + attempt) % lex.parts.len()];

    // Match kebab-case or snake_case identifier-like literals naturally
    let has_space = original.contains(' ');
    if !has_space && placeholders.is_empty() {
        let sep = if original.contains('-') {
            "-"
        } else if original.contains('_') {
            "_"
        } else {
            "-"
        };
        let n1 = lex.nouns[(digest[4] as usize + attempt) % lex.nouns.len()];
        let n2 = lex.parts[(digest[5] as usize + attempt) % lex.parts.len()];
        if attempt == 0 {
            return format!("{adj}{sep}{n1}{sep}{n2}");
        }
        let n3 = lex.nouns[(digest[6] as usize + attempt) % lex.nouns.len()];
        return format!("{adj}{sep}{n1}{sep}{n2}{sep}{n3}");
    }

    let mut base = if attempt == 0 {
        format!("{subj} {state}")
    } else {
        format!("{adj} {subj} {part} {state}")
    };
    if !placeholders.is_empty() {
        base.push_str(": ");
        base.push_str(&placeholders.join(" / "));
    }
    base
}

/// Build a combinatorial, natural developer comment with zero hex tags or bracketed prefixes.
fn format_natural_comment(prefix: &str, lex: &ThemeLexicon, digest: &[u8; 32], attempt: usize) -> String {
    let na = lex.comment_actions.len();
    let ns = lex.comment_subjects.len();
    let nc = lex.comment_contexts.len();
    let a = (digest[0] as usize + attempt) % na;
    let s = (digest[1] as usize + (attempt / na)) % ns;
    let c = (digest[2] as usize + (attempt / (na * ns))) % nc;
    if attempt < na * ns {
        format!(
            "{prefix}{} {} {}",
            lex.comment_actions[a], lex.comment_subjects[s], lex.comment_contexts[c]
        )
    } else {
        let extra = lex.parts[(digest[3] as usize + attempt) % lex.parts.len()];
        format!(
            "{prefix}{} {} ({extra}) {}",
            lex.comment_actions[a], lex.comment_subjects[s], lex.comment_contexts[c]
        )
    }
}

/// Check lexical surroundings to avoid corrupting XML envelope tags, stdlib qualifiers, or CLI flags.
fn is_protected_lexical_context(text: &str, start: usize, end: usize) -> bool {
    let before = &text[..start];
    let after = &text[end..];
    // XML / harness framing tags: `<USER_REQUEST>`, `</ADDITIONAL_METADATA>`
    if (before.ends_with('<') || before.ends_with("</")) && after.starts_with(['>', ' ']) {
        return true;
    }
    // CLI flags: `--max-depth`, `--no_proxy`
    if before.ends_with("--") {
        return true;
    }
    // Direct stdlib / framework qualified member (`std::collections`, `React.useState`, `fmt.Sprintf`)
    if STDLIB_QUALIFIERS.iter().any(|q| before.ends_with(q)) {
        return true;
    }
    false
}

fn decoy_json(value: &mut Value, modules: &[(&str, &str)], n: &mut usize, depth: usize) {
    if depth >= MAX_JSON_DEPTH {
        if let Value::String(s) = value {
            *n += 1;
            *s = decoy_module_text(modules, s.chars().count(), *n);
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
                        let (base_path, _) = modules[*n % modules.len()];
                        *s = base_path.to_string();
                        continue;
                    }
                }
                decoy_json(v, modules, n, depth + 1);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| decoy_json(v, modules, n, depth + 1)),
        Value::String(s) => {
            *n += 1;
            *s = decoy_module_text(modules, s.chars().count(), *n);
        }
        _ => {}
    }
}

fn decoy_module_text(modules: &[(&str, &str)], target_len: usize, idx: usize) -> String {
    if target_len == 0 || modules.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(target_len);
    let mut cur = idx;
    while out.chars().count() < target_len {
        let (_, chunk) = modules[cur % modules.len()];
        out.push_str(chunk);
        if out.chars().count() < target_len {
            out.push('\n');
        }
        cur += 1;
    }
    out.chars().take(target_len).collect()
}

/// Grammatical, role-preserving cover identifier generator.
///
/// Matches the original identifier's case style and structural role:
/// - `SCREAMING_SNAKE`: preserves `MAX_`/`MIN_`/`DEFAULT_` prefixes -> `MAX_MISTING_PRESSURE`
/// - `PascalCase`: preserves conventional suffixes (`Config`/`Error`/`Service`/…) -> `CanopyConfig`
/// - Verb-prefixed functions (`compute_*`, `is_*`, `check*`): emits `verb_noun` / `verbNoun`
/// - General `snake_case` / `camelCase`: emits crisp 2-word `noun_part` / `nounPart`
fn format_cover_symbol_from_digest(symbol: &str, theme: CoverTheme, digest: &[u8; 32], attempt: usize) -> String {
    let lex = lexicon_for(theme);
    let nn = lex.nouns.len();
    let np = lex.parts.len();
    let nv = lex.verbs.len();
    let na = lex.adjectives.len();

    let noun = lex.nouns[(digest[0] as usize + attempt) % nn];
    let part = lex.parts[(digest[1] as usize + attempt / nn) % np];
    let adj = lex.adjectives[(digest[2] as usize + attempt) % na];
    let verb = lex.verbs[(digest[3] as usize + attempt) % nv];
    let extra = lex.parts[(digest[4] as usize + attempt) % np];

    // 1. SCREAMING_SNAKE_CASE constants
    if symbol.chars().all(|c| !c.is_lowercase()) {
        if let Some(prefix) = CONST_PREFIXES.iter().find(|p| symbol.starts_with(**p)) {
            return if attempt == 0 {
                format!("{prefix}{}_{}", noun.to_uppercase(), part.to_uppercase())
            } else {
                format!(
                    "{prefix}{}_{}_{}",
                    adj.to_uppercase(),
                    noun.to_uppercase(),
                    part.to_uppercase()
                )
            };
        }
        return if attempt == 0 {
            format!("{}_{}", noun.to_uppercase(), part.to_uppercase())
        } else {
            format!(
                "{}_{}_{}",
                adj.to_uppercase(),
                noun.to_uppercase(),
                extra.to_uppercase()
            )
        };
    }

    // 2. PascalCase types / structs / classes / errors
    if symbol.chars().next().is_some_and(|c| c.is_uppercase()) {
        if let Some(suffix) = PRESERVED_TYPE_SUFFIXES
            .iter()
            .find(|s| symbol.ends_with(**s) && symbol.len() > s.len() + 2)
        {
            return if attempt == 0 {
                format!("{}{suffix}", capitalize(noun))
            } else {
                format!("{}{}{suffix}", capitalize(adj), capitalize(noun))
            };
        }
        return if attempt == 0 {
            format!("{}{}", capitalize(noun), capitalize(part))
        } else {
            format!("{}{}{}", capitalize(adj), capitalize(noun), capitalize(extra))
        };
    }

    // 3. snake_case functions & variables
    if symbol.contains('_') {
        let lower_first = symbol.split('_').next().unwrap_or("");
        if matches!(lower_first, "is" | "has" | "can" | "should" | "on") {
            return if attempt == 0 {
                format!("{lower_first}_{noun}_{part}")
            } else {
                format!("{lower_first}_{adj}_{noun}_{extra}")
            };
        }
        if CODE_VERB_PREFIXES.contains(&lower_first) {
            return if attempt == 0 {
                format!("{verb}_{noun}_{part}")
            } else {
                format!("{verb}_{adj}_{noun}_{extra}")
            };
        }
        return if attempt == 0 {
            format!("{noun}_{part}")
        } else {
            format!("{adj}_{noun}_{extra}")
        };
    }

    // 4. camelCase functions & variables
    let camel_prefix: String = symbol.chars().take_while(|c| c.is_ascii_lowercase()).collect();
    if matches!(camel_prefix.as_str(), "is" | "has" | "can" | "should" | "on") {
        return if attempt == 0 {
            format!("{camel_prefix}{}{}", capitalize(noun), capitalize(part))
        } else {
            format!(
                "{camel_prefix}{}{}{}",
                capitalize(adj),
                capitalize(noun),
                capitalize(extra)
            )
        };
    }
    if CODE_VERB_PREFIXES.contains(&camel_prefix.as_str()) {
        return if attempt == 0 {
            format!("{verb}{}{}", capitalize(noun), capitalize(part))
        } else {
            format!("{verb}{}{}{}", capitalize(adj), capitalize(noun), capitalize(extra))
        };
    }
    if attempt == 0 {
        format!("{noun}{}", capitalize(part))
    } else {
        format!("{adj}{}{}", capitalize(noun), capitalize(extra))
    }
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
    use crate::config::ToolCallSecretPolicy;
    use crate::restore::restore_response;
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
        let idx = chars.len() - 2;
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
        // Zero synthetic fingerprints (`lit_`, `(#xxxx)`, `BotanicalSensor`, `HIDE_`)
        for fp in ["lit_", "(#", "BotanicalSensor", "HIDE_"] {
            assert!(
                !out.vendor_payload.contains(fp),
                "leaked {fp} in {}",
                out.vendor_payload
            );
        }
        assert!(out.vendor_payload.starts_with("// "), "{}", out.vendor_payload);
        assert_eq!(vault.restore_text(&out.vendor_payload).0, src);
    }

    #[test]
    fn hash_comments_and_stdlib_symbols_behave_cleanly() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.strict_literal_masking = false;
        let vault = PrivacyVault::new();
        let src = "#!/usr/bin/env python3\n# Internal proprietary trading loop\n#[derive(Debug)]\ncolor = #1a2b3c\nif isinstance(state, AbortController): serde_json.unwrap_or_else()\ncompute_margin_liquidation()";
        let out = AllHideEngine::process(src, TrafficCategory::InteractivePrompt, &cfg, &vault);
        assert!(out.vendor_payload.starts_with("#!/usr/bin/env python3\n# "));
        assert!(!out.vendor_payload.contains("BotanicalSensor"));
        assert!(!out.vendor_payload.contains("(#"));
        assert!(!out.vendor_payload.contains("proprietary trading"));
        assert!(out.vendor_payload.contains("#[derive(Debug)]"));
        assert!(out.vendor_payload.contains("#1a2b3c"));
        assert!(out.vendor_payload.contains("isinstance"));
        assert!(out.vendor_payload.contains("AbortController"));
        assert!(out.vendor_payload.contains("serde_json.unwrap_or_else()"));
        assert!(!out.vendor_payload.contains("compute_margin_liquidation"));
        assert_eq!(vault.restore_text(&out.vendor_payload).0, src);
    }

    #[test]
    fn all_hide_keyed_camouflage_isolates_vaults() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.strict_literal_masking = true;
        let src = "// Confidential risk engine check\npub fn check_risk_threshold(secret_flag: &str) -> bool { check_order_book(\"margin-tier\") }";
        let v1 = PrivacyVault::new();
        let v2 = PrivacyVault::new();
        let o1 = AllHideEngine::process_with_scope(src, TrafficCategory::InteractivePrompt, &cfg, &v1, Some("s1"));
        let o2 = AllHideEngine::process_with_scope(src, TrafficCategory::InteractivePrompt, &cfg, &v2, Some("s1"));
        assert_ne!(o1.vendor_payload, o2.vendor_payload);
        for marker in ["BotanicalSensor", "HIDE_", "sk-sem", "placeholder", "lit_", "(#"] {
            assert!(!o1.vendor_payload.contains(marker), "{}", o1.vendor_payload);
        }
        assert_eq!(
            v1.matcher_for_scope(Some("s1"))
                .restore(&o1.vendor_payload, None, true)
                .0,
            src
        );
    }

    #[test]
    fn ai_can_read_natural_cover_code_and_submit_lossless_edit_tool_call() {
        let mut cfg = all_hide_cfg();
        cfg.all_hide.strict_literal_masking = true;
        let vault = PrivacyVault::new();

        let original_code = r#"import { format } from "node:util";
// Reconcile HFT margin settlement before market close
pub struct MarginConfig { pub max_leverage: u32 }
pub fn settle_account_balance(cfg: &MarginConfig, account_balance: i64) -> Result<i64, String> {
    if account_balance < 0 {
        return Err(format!("margin breach on account {}", account_balance));
    }
    Ok(account_balance)
}"#;

        let req = json!({
            "systemInstruction": {
                "role": "user",
                "parts": [{"text": "You are an assistant. Use edit_file with TargetFile and ReplacementContent."}]
            },
            "tools": [{
                "functionDeclarations": [{
                    "name": "edit_file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "TargetFile": {"type": "string"},
                            "TargetContent": {"type": "string"},
                            "ReplacementContent": {"type": "string"}
                        }
                    }
                }]
            }],
            "contents": [{
                "role": "user",
                "parts": [{"text": format!("<USER_REQUEST>\nFix zero balance handling in src/margin_engine.rs:\n```rust\n{original_code}\n```\n</USER_REQUEST>")}]
            }]
        });

        let out = AllHideEngine::process_with_scope(
            &req.to_string(),
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
            Some("harness:antigravity"),
        );

        let vendor_json: Value = serde_json::from_str(&out.vendor_payload).unwrap();
        let vendor_prompt = vendor_json["contents"][0]["parts"][0]["text"].as_str().unwrap();

        // 1. Harness framing, imports, format placeholders, and tool names remain intact
        assert!(vendor_prompt.contains("<USER_REQUEST>"));
        assert!(vendor_prompt.contains("</USER_REQUEST>"));
        assert!(vendor_prompt.contains("\"node:util\""));
        assert!(vendor_prompt.contains("{}"));
        assert!(vendor_json["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .unwrap()
            .contains("edit_file with TargetFile and ReplacementContent"));

        // 2. Zero proprietary terms or synthetic fingerprints leak to the vendor
        for forbidden in [
            "MarginConfig",
            "max_leverage",
            "settle_account_balance",
            "account_balance",
            "margin breach",
            "HFT margin",
            "lit_",
            "(#",
        ] {
            assert!(
                !vendor_prompt.contains(forbidden),
                "leaked {forbidden} in {vendor_prompt}"
            );
        }
        // Role suffix `Config` is preserved so the AI sees a natural `*Config` struct
        assert!(vendor_prompt.contains("Config"), "{vendor_prompt}");

        // 3. Simulate the AI reading the camouflaged code and emitting an edit_file tool call
        //    fixing `<= 0` instead of `< 0` using the camouflaged symbols & cover string!
        let cover_code = vendor_prompt
            .split("```rust\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        let cover_file = vendor_prompt
            .split("handling in ")
            .nth(1)
            .unwrap()
            .split(':')
            .next()
            .unwrap();
        let fixed_cover_code = cover_code.replace("< 0", "<= 0");

        let ai_response = json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "name": "edit_file",
                            "args": {
                                "TargetFile": cover_file,
                                "TargetContent": cover_code,
                                "ReplacementContent": fixed_cover_code
                            }
                        }
                    }]
                }
            }]
        });

        // 4. Restore the AI's response back to the local codebase
        let matcher = vault.matcher_for_scope(Some("harness:antigravity"));
        let (restored_str, restored_count, _) =
            restore_response(&matcher, &ai_response.to_string(), ToolCallSecretPolicy::FileEditsOnly);
        assert!(restored_count > 0);
        let restored_json: Value = serde_json::from_str(&restored_str).unwrap();
        let args = &restored_json["candidates"][0]["content"]["parts"][0]["functionCall"]["args"];
        assert_eq!(args["TargetFile"].as_str().unwrap(), "src/margin_engine.rs");
        assert_eq!(args["TargetContent"].as_str().unwrap(), original_code);
        assert_eq!(
            args["ReplacementContent"].as_str().unwrap(),
            original_code.replace("< 0", "<= 0")
        );
    }

    #[test]
    fn all_hide_preserves_anthropic_and_openai_system_prompts_while_camouflaging_user_code() {
        let cfg = all_hide_cfg();
        let vault = PrivacyVault::new();

        // Anthropic Messages API with top-level `system` prompt + secret inside system prompt
        let anthropic = json!({
            "model": "claude-sonnet-4-5",
            "system": [{"type": "text", "text": "You are an IDE coding assistant. Always use edit_file with old_string and new_string. Secret: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"}],
            "messages": [{"role": "user", "content": "Fix settle_margin_order(\"risk breach\")"}]
        });
        let out_a = AllHideEngine::process(&anthropic.to_string(), TrafficCategory::InteractivePrompt, &cfg, &vault);
        let parsed_a: Value = serde_json::from_str(&out_a.vendor_payload).unwrap();
        let sys_text = parsed_a["system"][0]["text"].as_str().unwrap();
        assert!(sys_text.contains("old_string and new_string"), "{sys_text}");
        assert!(!sys_text.contains("sk-ant-api03-abcdefghijklmnopqrstuvwxyz"));
        let user_text = parsed_a["messages"][0]["content"].as_str().unwrap();
        assert!(!user_text.contains("settle_margin_order"), "{user_text}");
        assert!(!user_text.contains("risk breach"), "{user_text}");
        assert_eq!(
            vault.restore_text(user_text).0,
            "Fix settle_margin_order(\"risk breach\")"
        );

        // OpenAI Chat Completions with `role: "developer"` system prompt
        let openai = json!({
            "model": "gpt-5.2",
            "messages": [
                {"role": "developer", "content": "Follow apply_patch tool instructions strictly."},
                {"role": "user", "content": "Refactor compute_risk_matrix()"}
            ]
        });
        let out_o = AllHideEngine::process(&openai.to_string(), TrafficCategory::InteractivePrompt, &cfg, &vault);
        let parsed_o: Value = serde_json::from_str(&out_o.vendor_payload).unwrap();
        assert_eq!(
            parsed_o["messages"][0]["content"].as_str().unwrap(),
            "Follow apply_patch tool instructions strictly."
        );
        let u_o = parsed_o["messages"][1]["content"].as_str().unwrap();
        assert!(!u_o.contains("compute_risk_matrix"), "{u_o}");
        assert_eq!(vault.restore_text(u_o).0, "Refactor compute_risk_matrix()");
    }
}

use crate::chrome_bridge::is_reparse_or_symlink;
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
};

const JS_CONTENT_TYPE: &str = "application/javascript; charset=utf-8";
const CSS_CONTENT_TYPE: &str = "text/css; charset=utf-8";

#[derive(Debug, Clone)]
pub struct UiBundle {
    pub html: String,
    pub assets: HashMap<String, (&'static str, Vec<u8>)>,
}

fn attribute<'a>(mut attributes: &'a str, key: &str) -> Option<&'a str> {
    while !attributes.trim_start().is_empty() {
        attributes = attributes.trim_start();
        let end = attributes
            .find(|c: char| c.is_ascii_whitespace() || c == '=' || c == '/')
            .unwrap_or(attributes.len());
        if end == 0 {
            break;
        }
        let name = &attributes[..end];
        attributes = attributes[end..].trim_start();
        if !attributes.starts_with('=') {
            continue;
        }
        attributes = attributes[1..].trim_start();
        let value = if attributes.starts_with(['\'', '"']) {
            let quote = attributes.as_bytes()[0] as char;
            attributes = &attributes[1..];
            let end = attributes.find(quote)?;
            let value = &attributes[..end];
            attributes = &attributes[end + 1..];
            value
        } else {
            let end = attributes.find(char::is_whitespace).unwrap_or(attributes.len());
            let value = &attributes[..end];
            attributes = &attributes[end..];
            value
        };
        if name.eq_ignore_ascii_case(key) {
            return Some(value);
        }
    }
    None
}

fn parse_linked_assets(mut html: &str) -> Result<BTreeMap<String, &'static str>, String> {
    let mut assets = BTreeMap::new();
    while let Some(start) = html.find('<') {
        html = &html[start + 1..];
        if let Some(comment) = html.strip_prefix("!--") {
            let end = comment.find("-->").ok_or("HTML contains unterminated comment")?;
            html = &comment[end + 3..];
            continue;
        }
        let mut quote = None;
        let end = html
            .char_indices()
            .find_map(|(index, ch)| {
                match (quote, ch) {
                    (Some(open), close) if open == close => quote = None,
                    (None, '\'' | '"') => quote = Some(ch),
                    (None, '>') => return Some(index),
                    _ => {}
                }
                None
            })
            .ok_or("HTML contains unterminated tag")?;
        let tag = &html[..end];
        html = &html[end + 1..];
        let name_end = tag
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let (name, attributes) = tag.split_at(name_end);
        let name_lower = name.to_ascii_lowercase();
        let asset = match name_lower.as_str() {
            "script" => attribute(attributes, "src").map(|url| (url, JS_CONTENT_TYPE)),
            "link" => {
                let rel = attribute(attributes, "rel").unwrap_or("");
                let content_type = if rel.split_ascii_whitespace().any(|r| r == "stylesheet") {
                    Some(CSS_CONTENT_TYPE)
                } else if rel.split_ascii_whitespace().any(|r| r == "modulepreload") {
                    Some(JS_CONTENT_TYPE)
                } else {
                    None
                };
                if let Some(mime) = content_type {
                    let url = attribute(attributes, "href").ok_or("HTML asset link missing href")?;
                    Some((url, mime))
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some((url, content_type)) = asset {
            let path = url.split(['?', '#']).next().unwrap_or("");
            let path = path
                .strip_prefix('/')
                .or_else(|| path.strip_prefix("./"))
                .unwrap_or(path);
            if !path.starts_with("assets/")
                || path.contains(['\\', ':', '%', '&'])
                || path.split('/').any(|part| matches!(part, "" | "." | ".."))
            {
                return Err(format!("HTML asset must use a local /assets/ path: {url}"));
            }
            let ext_ok = (content_type == CSS_CONTENT_TYPE && path.ends_with(".css"))
                || (content_type == JS_CONTENT_TYPE && (path.ends_with(".js") || path.ends_with(".mjs")));
            if !ext_ok {
                return Err(format!("Unsupported asset extension: {url}"));
            }
            assets.insert(format!("/{path}"), content_type);
        }
        if matches!(name_lower.as_str(), "script" | "style") {
            let closing_tag = format!("</{name_lower}>");
            let end = html
                .find(&closing_tag)
                .ok_or_else(|| format!("HTML is missing {closing_tag}"))?;
            html = &html[end + closing_tag.len()..];
        }
    }
    if !(assets.values().any(|&m| m == JS_CONTENT_TYPE) && assets.values().any(|&m| m == CSS_CONTENT_TYPE)) {
        return Err("HTML must reference JavaScript and CSS assets".to_string());
    }
    Ok(assets)
}

fn mime_for_extra_asset_scan(name: &str) -> Option<&'static str> {
    let ext = Path::new(name).extension().and_then(|e| e.to_str())?;
    match ext.to_ascii_lowercase().as_str() {
        "woff2" => Some("font/woff2"),
        "woff" => Some("font/woff"),
        "png" => Some("image/png"),
        "svg" => Some("image/svg+xml"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        _ => None,
    }
}

fn is_safe_asset_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

impl UiBundle {
    pub fn load_from_dir(root_dir: &Path, html_filename: &str) -> Result<Self, String> {
        if !root_dir.is_dir() || is_reparse_or_symlink(root_dir) {
            return Err(format!(
                "UI resource directory is missing or unsafe: {}",
                root_dir.display()
            ));
        }
        let html_path = root_dir.join(html_filename);
        if is_reparse_or_symlink(&html_path) || !html_path.is_file() {
            return Err(format!("UI entrypoint is missing: {}", html_path.display()));
        }
        let html =
            fs::read_to_string(&html_path).map_err(|e| format!("Failed to read {}: {e}", html_path.display()))?;
        if !html.contains("</head>") {
            return Err(format!("{} is missing </head>", html_path.display()));
        }

        let linked = parse_linked_assets(&html)?;
        let canonical_root = fs::canonicalize(root_dir)
            .map_err(|e| format!("Failed to resolve UI resource root {}: {e}", root_dir.display()))?;
        let assets_dir = root_dir.join("assets");
        if is_reparse_or_symlink(&assets_dir) || !assets_dir.is_dir() {
            return Err(format!("UI assets directory is missing: {}", assets_dir.display()));
        }
        let canonical_assets = fs::canonicalize(&assets_dir)
            .map_err(|e| format!("Failed to resolve assets directory {}: {e}", assets_dir.display()))?;
        if !canonical_assets.starts_with(&canonical_root) {
            return Err("UI assets directory escapes root directory".to_string());
        }

        let mut expected = linked;
        for entry in fs::read_dir(&assets_dir).map_err(|e| format!("Failed to list {}: {e}", assets_dir.display()))? {
            let entry = entry.map_err(|e| format!("Failed to inspect asset entry: {e}"))?;
            let path = entry.path();
            if is_reparse_or_symlink(&path) || !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !is_safe_asset_name(name) {
                continue;
            }
            let Some(mime) = mime_for_extra_asset_scan(name) else {
                continue;
            };
            expected.entry(format!("/assets/{name}")).or_insert(mime);
        }

        let mut assets = HashMap::new();
        for (url, content_type) in expected {
            let rel = url.trim_start_matches('/');
            let file_path = root_dir.join(rel);
            if is_reparse_or_symlink(&file_path) || !file_path.is_file() {
                return Err(format!("Missing required UI asset {url} at {}", file_path.display()));
            }
            let resolved = fs::canonicalize(&file_path).map_err(|e| format!("Cannot resolve UI asset {url}: {e}"))?;
            if !resolved.starts_with(&canonical_assets) {
                return Err(format!("UI asset {url} escapes assets directory"));
            }
            let bytes = fs::read(&resolved).map_err(|e| format!("Failed to read UI asset {url}: {e}"))?;
            assets.insert(url, (content_type, bytes));
        }

        Ok(Self { html, assets })
    }

    pub fn render_html(&self, sys_locale: &str, nonce: &str, token_var: &str, token: &str) -> String {
        let token_json = serde_json::to_string(token)
            .expect("admin token must serialize as JSON string")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        let token_script = format!("<script nonce=\"{nonce}\">window.{token_var}={token_json};</script></head>");
        self.html
            .replacen("<html lang=\"zh-CN\">", &format!("<html lang=\"{sys_locale}\">"), 1)
            .replace("__HIDE_GO_LOCALE__", sys_locale)
            .replace("nonce=\"__HIDE_GO_NONCE__\"", &format!("nonce=\"{nonce}\""))
            .replacen("</head>", &token_script, 1)
    }

    pub fn serve_asset(&self, req_path: &str) -> Response {
        if let Some((content_type, bytes)) = self.assets.get(req_path) {
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, *content_type),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                bytes.clone(),
            )
                .into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

pub fn build_nonce_csp(nonce: &str) -> String {
    format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
}

pub fn resolve_resources_dir(exe_dir: Option<&Path>) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("resources"));
        #[cfg(target_os = "macos")]
        candidates.push(dir.join("../Resources"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let direct = dir.join("resources");
            if !candidates.contains(&direct) {
                candidates.push(direct);
            }
            #[cfg(target_os = "macos")]
            {
                let mac_res = dir.join("../Resources");
                if !candidates.contains(&mac_res) {
                    candidates.push(mac_res);
                }
            }
        }
    }
    candidates.into_iter().find(|p| p.is_dir() && !is_reparse_or_symlink(p))
}

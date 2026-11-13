use std::{collections::BTreeMap, env, fs, path::PathBuf};

const JS_CONTENT_TYPE: &str = "application/javascript; charset=utf-8";
const CSS_CONTENT_TYPE: &str = "text/css; charset=utf-8";

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
            let end = attributes
                .find(quote)
                .expect("dist/index.html contains an unterminated attribute");
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

fn linked_assets(mut html: &str) -> BTreeMap<String, &'static str> {
    let mut assets = BTreeMap::new();
    while let Some(start) = html.find('<') {
        html = &html[start + 1..];
        if let Some(comment) = html.strip_prefix("!--") {
            let end = comment
                .find("-->")
                .expect("dist/index.html contains an unterminated comment");
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
            .expect("dist/index.html contains an unterminated tag");
        let tag = &html[..end];
        html = &html[end + 1..];
        let name_end = tag
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let (name, attributes) = tag.split_at(name_end);
        let asset = match name {
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
                content_type.map(|content_type| {
                    let url =
                        attribute(attributes, "href").expect("dist/index.html contains an asset link without href");
                    (url, content_type)
                })
            }
            _ => None,
        };
        if let Some((url, content_type)) = asset {
            let path = url.split(['?', '#']).next().unwrap_or("");
            let path = path
                .strip_prefix('/')
                .or_else(|| path.strip_prefix("./"))
                .unwrap_or(path);
            assert!(
                path.starts_with("assets/")
                    && !path.contains(['\\', ':', '%', '&'])
                    && path.split('/').all(|part| !matches!(part, "" | "." | "..")),
                "dist/index.html asset must be a local /assets/ path: {url}"
            );
            assert!(
                (content_type == CSS_CONTENT_TYPE && path.ends_with(".css"))
                    || (content_type == JS_CONTENT_TYPE && (path.ends_with(".js") || path.ends_with(".mjs"))),
                "dist/index.html asset has an unsupported extension: {url}"
            );
            assets.insert(format!("/{path}"), content_type);
        }
        if matches!(name, "script" | "style") {
            let closing_tag = format!("</{name}>");
            let end = html
                .find(&closing_tag)
                .unwrap_or_else(|| panic!("dist/index.html is missing {closing_tag}"));
            html = &html[end + closing_tag.len()..];
        }
    }
    assert!(
        assets.values().any(|&mime| mime == JS_CONTENT_TYPE) && assets.values().any(|&mime| mime == CSS_CONTENT_TYPE),
        "dist/index.html must reference JavaScript and stylesheet assets; rebuild the UI first"
    );
    assets
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest_dir.join("../dist");
    let index = dist.join("index.html");
    println!("cargo:rerun-if-changed={}", index.display());
    let html = fs::read_to_string(&index)
        .unwrap_or_else(|err| panic!("Cannot read {}: {err}; rebuild the UI first", index.display()));
    assert!(
        html.contains("</head>"),
        "dist/index.html is missing </head> for desktop token injection"
    );
    let dist = dist.canonicalize().expect("Cannot resolve dist directory");
    let mut generated = format!(
        "const EMBEDDED_INDEX_HTML: &str = include_str!({:?});\n\
         const EMBEDDED_ASSETS: &[(&str, &str, &[u8])] = &[\n",
        dist.join("index.html")
    );
    let mut embedded = linked_assets(&html);
    // Files referenced from inside the bundle (fonts, images imported by CSS/JS).
    let assets_dir = dist.join("assets");
    println!("cargo:rerun-if-changed={}", assets_dir.display());
    for entry in fs::read_dir(&assets_dir).expect("Cannot read dist/assets; rebuild the UI first") {
        let path = entry.expect("dist/assets entry").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let content_type = match path.extension().and_then(|e| e.to_str()) {
            Some("woff2") => "font/woff2",
            Some("woff") => "font/woff",
            Some("png") => "image/png",
            Some("svg") => "image/svg+xml",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            _ => continue,
        };
        if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            embedded.entry(format!("/assets/{name}")).or_insert(content_type);
        }
    }
    for (url, content_type) in embedded {
        let path = dist.join(&url[1..]);
        println!("cargo:rerun-if-changed={}", path.display());
        let resolved = path.canonicalize().unwrap_or_else(|err| {
            panic!(
                "Cannot read asset {url} referenced by dist/index.html at {}: {err}; rebuild the UI first",
                path.display()
            )
        });
        assert!(
            resolved.starts_with(&dist) && resolved.is_file(),
            "dist/index.html asset is not a file inside dist: {url}"
        );
        generated.push_str(&format!("    ({url:?}, {content_type:?}, include_bytes!({path:?})),\n"));
    }
    generated.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("embedded_assets.rs");
    fs::write(&output, generated).unwrap_or_else(|err| panic!("Cannot write {}: {err}", output.display()));
}

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "bw-passport-dedup", version, about = "Deduplicate Bitwarden JSON exports")]
struct Args {
    /// Bitwarden JSON export file
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Output file (defaults to <input>.dedup.json)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it exists
    #[arg(long, action = ArgAction::SetTrue)]
    force: bool,

    /// Show what would be removed without writing output
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Write pretty-printed JSON
    #[arg(long, action = ArgAction::SetTrue)]
    pretty: bool,

    /// Keep strategy when duplicates are found
    #[arg(long, value_enum, default_value_t = Keep::First)]
    keep: Keep,

    /// Config file (TOML)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Ignore any keys with these names, anywhere in the item
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "KEYS"
    )]
    ignore_key: Option<Vec<String>>,

    /// Ignore specific paths (dot-separated), relative to each item
    #[arg(long, value_delimiter = ',', value_name = "PATHS")]
    ignore_path: Option<Vec<String>>,

    /// Trim whitespace from all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    trim_strings: bool,

    /// Lowercase all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    lowercase_strings: bool,

    /// Sort login.uris entries by URI before hashing
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    sort_uris: bool,

    /// Deduplication keys (comma-separated). Overrides config.
    #[arg(long, value_delimiter = ',', value_name = "KEYS")]
    policy_key: Option<Vec<DedupKey>>,
}

#[derive(Copy, Clone, Debug, Deserialize, ValueEnum, PartialEq, Eq)]
enum Keep {
    First,
    Last,
    Newest,
    Oldest,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct Config {
    dedup: DedupConfig,
    ignore: IgnoreConfig,
    normalize: NormalizeConfig,
    output: OutputConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct DedupConfig {
    keep: Keep,
    policy_keys: Vec<DedupKey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct IgnoreConfig {
    keys: Vec<String>,
    paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct NormalizeConfig {
    trim_strings: bool,
    lowercase_strings: bool,
    sort_uris: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct OutputConfig {
    pretty: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DedupKey {
    Domain,
    Username,
    Password,
    Name,
    Uri,
    Totp,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dedup: DedupConfig::default(),
            ignore: IgnoreConfig::default(),
            normalize: NormalizeConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            keep: Keep::First,
            policy_keys: vec![DedupKey::Domain, DedupKey::Username, DedupKey::Password],
        }
    }
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self {
            keys: vec![
                "id".to_string(),
                "revisionDate".to_string(),
                "creationDate".to_string(),
                "passwordHistory".to_string(),
            ],
            paths: Vec::new(),
        }
    }
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        Self {
            trim_strings: false,
            lowercase_strings: false,
            sort_uris: true,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self { pretty: false }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = &args.input;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(input));

    if output.exists() && !args.force && !args.dry_run {
        anyhow::bail!(
            "output file already exists: {} (use --force to overwrite)",
            output.display()
        );
    }

    let mut config = load_config(args.config.as_deref())?;

    if args.keep != Keep::First {
        config.dedup.keep = args.keep;
    }
    if let Some(keys) = args.policy_key.clone() {
        config.dedup.policy_keys = keys;
    }
    if let Some(keys) = args.ignore_key.clone() {
        config.ignore.keys = keys;
    }
    if let Some(paths) = args.ignore_path.clone() {
        config.ignore.paths = paths;
    }
    if args.trim_strings {
        config.normalize.trim_strings = true;
    }
    if args.lowercase_strings {
        config.normalize.lowercase_strings = true;
    }
    if args.sort_uris != config.normalize.sort_uris {
        config.normalize.sort_uris = args.sort_uris;
    }
    if args.pretty {
        config.output.pretty = true;
    }

    let input_data = fs::read_to_string(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;

    let mut root: Value = serde_json::from_str(&input_data)
        .with_context(|| format!("failed to parse JSON from {}", input.display()))?;

    let items = root
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("expected top-level 'items' array in Bitwarden export")?;

    let ignore_keys = config
        .ignore
        .keys
        .iter()
        .map(|s| s.to_string())
        .collect::<HashSet<_>>();

    let ignore_paths = config
        .ignore
        .paths
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_path(s))
        .collect::<Vec<_>>();

    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<Value> = Vec::with_capacity(items.len());
    let mut removed = 0usize;

    for item in items.drain(..) {
        let key = build_key(
            &item,
            &config,
            &ignore_keys,
            &ignore_paths,
        );

        match seen.get(&key).copied() {
            None => {
                let index = deduped.len();
                deduped.push(item);
                seen.insert(key, index);
            }
            Some(existing_index) => {
                let replace = should_replace(
                    &deduped[existing_index],
                    &item,
                    config.dedup.keep,
                );
                if replace {
                    deduped[existing_index] = item;
                }
                removed += 1;
            }
        }
    }

    let total = deduped.len() + removed;
    root["items"] = Value::Array(deduped);

    println!(
        "Items: {} -> {} (removed {})",
        total,
        root["items"].as_array().map(|v| v.len()).unwrap_or(0),
        removed
    );

    if args.dry_run {
        return Ok(());
    }

    let output_data = if config.output.pretty {
        serde_json::to_string_pretty(&root)?
    } else {
        serde_json::to_string(&root)?
    };

    fs::write(&output, output_data)
        .with_context(|| format!("failed to write output file {}", output.display()))?;

    println!("Wrote {}", output.display());

    Ok(())
}

fn default_output_path(input: &Path) -> PathBuf {
    let mut output = input.to_path_buf();
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
    let suffix = if ext.is_empty() { "dedup.json" } else { "dedup.json" };

    let file_name = input
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("output");

    let new_name = if ext.is_empty() {
        format!("{}.{}", file_name, suffix)
    } else {
        format!("{}.{}", file_name.trim_end_matches(ext).trim_end_matches('.'), suffix)
    };

    output.set_file_name(new_name);
    output
}

fn parse_path(path: &str) -> Vec<String> {
    path.split('.')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn build_key(
    item: &Value,
    config: &Config,
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
) -> String {
    if !config.dedup.policy_keys.is_empty() {
        let mut policy_value = build_policy_value(item, &config.dedup.policy_keys);
        if config.normalize.sort_uris {
            sort_login_uris(&mut policy_value);
        }
        normalize_strings(
            &mut policy_value,
            config.normalize.trim_strings,
            config.normalize.lowercase_strings,
        );
        let canonical = canonicalize(&policy_value);
        return serde_json::to_string(&canonical).unwrap_or_default();
    }

    let mut working = item.clone();
    remove_keys_anywhere(&mut working, ignore_keys);
    for path in ignore_paths {
        remove_path(&mut working, path);
    }
    if config.normalize.sort_uris {
        sort_login_uris(&mut working);
    }
    normalize_strings(
        &mut working,
        config.normalize.trim_strings,
        config.normalize.lowercase_strings,
    );
    let canonical = canonicalize(&working);
    serde_json::to_string(&canonical).unwrap_or_default()
}

fn build_policy_value(item: &Value, keys: &[DedupKey]) -> Value {
    let mut map = Map::new();
    for key in keys {
        match key {
            DedupKey::Domain => {
                let domains = extract_domains(item);
                map.insert("domain".to_string(), Value::Array(domains));
            }
            DedupKey::Username => {
                map.insert("username".to_string(), extract_login_field(item, "username"));
            }
            DedupKey::Password => {
                map.insert("password".to_string(), extract_login_field(item, "password"));
            }
            DedupKey::Name => {
                map.insert(
                    "name".to_string(),
                    item.get("name").cloned().unwrap_or(Value::Null),
                );
            }
            DedupKey::Uri => {
                let uris = extract_uris(item);
                map.insert("uri".to_string(), Value::Array(uris));
            }
            DedupKey::Totp => {
                map.insert("totp".to_string(), extract_login_field(item, "totp"));
            }
        }
    }
    Value::Object(map)
}

fn extract_login_field(item: &Value, field: &str) -> Value {
    item.get("login")
        .and_then(Value::as_object)
        .and_then(|login| login.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn extract_uris(item: &Value) -> Vec<Value> {
    let mut uris = Vec::new();
    if let Some(login) = item.get("login").and_then(Value::as_object) {
        if let Some(Value::Array(items)) = login.get("uris") {
            for entry in items {
                match entry {
                    Value::Object(map) => {
                        if let Some(Value::String(uri)) = map.get("uri") {
                            uris.push(Value::String(uri.clone()));
                        }
                    }
                    Value::String(uri) => uris.push(Value::String(uri.clone())),
                    _ => {}
                }
            }
        }
    }
    uris
}

fn extract_domains(item: &Value) -> Vec<Value> {
    let mut domains: Vec<String> = Vec::new();
    for uri_value in extract_uris(item) {
        if let Value::String(uri) = uri_value {
            if let Some(host) = extract_domain_from_uri(&uri) {
                domains.push(host);
            } else {
                domains.push(uri);
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains.into_iter().map(Value::String).collect()
}

fn extract_domain_from_uri(uri: &str) -> Option<String> {
    let without_scheme = uri.split("://").nth(1).unwrap_or(uri);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host_port.split('@').last().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn remove_keys_anywhere(value: &mut Value, ignore_keys: &HashSet<String>) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if ignore_keys.contains(&key) {
                    map.remove(&key);
                } else if let Some(child) = map.get_mut(&key) {
                    remove_keys_anywhere(child, ignore_keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_keys_anywhere(item, ignore_keys);
            }
        }
        _ => {}
    }
}

fn remove_path(value: &mut Value, path: &[String]) {
    if path.is_empty() {
        return;
    }

    let mut current = value;
    for (index, segment) in path.iter().enumerate() {
        match current {
            Value::Object(map) => {
                if index == path.len() - 1 {
                    map.remove(segment);
                    return;
                }
                if let Some(next) = map.get_mut(segment) {
                    current = next;
                } else {
                    return;
                }
            }
            _ => return,
        }
    }
}

fn normalize_strings(value: &mut Value, trim_strings: bool, lowercase_strings: bool) {
    match value {
        Value::String(s) => {
            if trim_strings {
                let trimmed = s.trim().to_string();
                *s = trimmed;
            }
            if lowercase_strings {
                *s = s.to_ascii_lowercase();
            }
        }
        Value::Array(items) => {
            for item in items {
                normalize_strings(item, trim_strings, lowercase_strings);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                normalize_strings(value, trim_strings, lowercase_strings);
            }
        }
        _ => {}
    }
}

fn sort_login_uris(value: &mut Value) {
    let Value::Object(map) = value else { return };
    let Some(Value::Object(login)) = map.get_mut("login") else {
        return;
    };

    let Some(Value::Array(uris)) = login.get_mut("uris") else {
        return;
    };

    uris.sort_by(|a, b| {
        let a_key = uri_sort_key(a);
        let b_key = uri_sort_key(b);
        a_key.cmp(&b_key)
    });
}

fn uri_sort_key(value: &Value) -> String {
    match value {
        Value::Object(map) => map
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Value::String(s) => s.to_string(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut new_map = Map::with_capacity(map.len());
            for key in keys {
                if let Some(value) = map.get(key) {
                    new_map.insert(key.clone(), canonicalize(value));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(items) => {
            let canonical_items = items.iter().map(canonicalize).collect();
            Value::Array(canonical_items)
        }
        _ => value.clone(),
    }
}

fn should_replace(existing: &Value, candidate: &Value, keep: Keep) -> bool {
    match keep {
        Keep::First => false,
        Keep::Last => true,
        Keep::Newest => compare_dates(existing, candidate) == Ordering::Less,
        Keep::Oldest => compare_dates(existing, candidate) == Ordering::Greater,
    }
}

fn compare_dates(existing: &Value, candidate: &Value) -> Ordering {
    let existing_date = best_date(existing);
    let candidate_date = best_date(candidate);

    match (existing_date, candidate_date) {
        (Some(a), Some(b)) => a.cmp(b),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn best_date(item: &Value) -> Option<&str> {
    item.get("revisionDate")
        .and_then(Value::as_str)
        .or_else(|| item.get("creationDate").and_then(Value::as_str))
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    let default_path = PathBuf::from("config.toml");
    let config_path = path.unwrap_or(&default_path);

    if config_path.exists() {
        let contents = fs::read_to_string(config_path).with_context(|| {
            format!("failed to read config file {}", config_path.display())
        })?;
        let config: Config = toml::from_str(&contents).with_context(|| {
            format!("failed to parse config file {}", config_path.display())
        })?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

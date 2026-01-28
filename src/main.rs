use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
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

    /// Ignore any keys with these names, anywhere in the item
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "id,revisionDate,creationDate,passwordHistory"
    )]
    ignore_key: Vec<String>,

    /// Ignore specific paths (dot-separated), relative to each item
    #[arg(long, value_delimiter = ',')]
    ignore_path: Vec<String>,

    /// Trim whitespace from all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    trim_strings: bool,

    /// Lowercase all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    lowercase_strings: bool,

    /// Sort login.uris entries by URI before hashing
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    sort_uris: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Keep {
    First,
    Last,
    Newest,
    Oldest,
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

    let input_data = fs::read_to_string(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;

    let mut root: Value = serde_json::from_str(&input_data)
        .with_context(|| format!("failed to parse JSON from {}", input.display()))?;

    let items = root
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("expected top-level 'items' array in Bitwarden export")?;

    let ignore_keys = args
        .ignore_key
        .iter()
        .map(|s| s.to_string())
        .collect::<HashSet<_>>();

    let ignore_paths = args
        .ignore_path
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
            &ignore_keys,
            &ignore_paths,
            args.trim_strings,
            args.lowercase_strings,
            args.sort_uris,
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
                    args.keep,
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

    let output_data = if args.pretty {
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
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
    trim_strings: bool,
    lowercase_strings: bool,
    sort_uris: bool,
) -> String {
    let mut working = item.clone();
    remove_keys_anywhere(&mut working, ignore_keys);
    for path in ignore_paths {
        remove_path(&mut working, path);
    }
    if sort_uris {
        sort_login_uris(&mut working);
    }
    normalize_strings(&mut working, trim_strings, lowercase_strings);
    let canonical = canonicalize(&working);
    serde_json::to_string(&canonical).unwrap_or_default()
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

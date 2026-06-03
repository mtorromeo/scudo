use std::{collections::HashMap, sync::OnceLock};

use anyhow::{Context, Result, bail};
use regex::Regex;
use toml::Value;

use crate::config::{CommandPattern, ValidatedConfigMap, ValidatedProfileConfig};

pub struct ResolvedProfile {
    pub systemd_args: Vec<String>,
    pub exec: Option<String>,
    pub debug: bool,
    pub confirm: bool,
    pub match_log: Vec<String>,
}

type Properties = HashMap<String, Value>;

#[derive(Default)]
struct ProfileMeta {
    exec: Option<String>,
    debug: Option<bool>,
    confirm: Option<bool>,
}

/// Collect all profiles that match `command`, merge them in priority order
/// (glob < regex < exact), and build the systemd-run argument list.
pub fn resolve(configs: &ValidatedConfigMap, command: &str) -> Result<ResolvedProfile> {
    let mut exact_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut glob_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut regex_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();

    for (name, profile) in &configs.0 {
        match &profile.pattern {
            CommandPattern::Never => {}
            CommandPattern::Exact(p) if p == command => {
                exact_matches.push((name, profile));
            }
            CommandPattern::Glob(p) if p.matches(command) => {
                glob_matches.push((name, profile));
            }
            CommandPattern::Regex(p) if p.is_match(command) => {
                regex_matches.push((name, profile));
            }
            _ => {}
        }
    }

    if exact_matches.is_empty() && glob_matches.is_empty() && regex_matches.is_empty() {
        eprintln!("scudo: warning: no profile matched '{command}'");
    }

    let mut match_log: Vec<String> = Vec::new();
    let mut merged = Properties::new();
    let mut meta = ProfileMeta::default();

    for (name, profile) in glob_matches
        .iter()
        .chain(regex_matches.iter())
        .chain(exact_matches.iter())
    {
        let (kind, pattern) = match_description(&profile.pattern);
        match_log.push(format!("profile '{name}' matched {kind} '{pattern}'"));
        extend_chain_log(configs, name, 0, &mut match_log);

        let (props, m) = expand_extend(configs, profile, &mut Vec::new())?;
        merge_into(&mut merged, props)?;
        meta.exec = m.exec.or(meta.exec);
        meta.debug = m.debug.or(meta.debug);
        meta.confirm = m.confirm.or(meta.confirm);
    }

    build_args(merged, meta, match_log)
}

fn extend_chain_log(
    configs: &ValidatedConfigMap,
    profile_name: &str,
    depth: usize,
    log: &mut Vec<String>,
) {
    let Some(profile) = configs.0.get(profile_name) else {
        return;
    };
    let Some(ref parent_name) = profile.extend else {
        return;
    };
    let indent = " ".repeat(2 + depth * 3);
    log.push(format!("{indent}└─ extends '{parent_name}'"));
    extend_chain_log(configs, parent_name, depth + 1, log);
}

fn match_description(pattern: &CommandPattern) -> (&'static str, String) {
    match pattern {
        CommandPattern::Exact(p) => ("exact", p.clone()),
        CommandPattern::Glob(p) => ("glob", p.as_str().to_owned()),
        CommandPattern::Regex(p) => ("regex", p.as_str().to_owned()),
        CommandPattern::Never => ("never", String::new()),
    }
}

/// Recursively resolve `extend`, returning the fully-merged property map and
/// the metadata flags for this profile's chain.
fn expand_extend(
    configs: &ValidatedConfigMap,
    profile: &ValidatedProfileConfig,
    visited: &mut Vec<String>,
) -> Result<(Properties, ProfileMeta)> {
    let (mut base, parent_meta) = if let Some(parent_name) = &profile.extend {
        if visited.contains(parent_name) {
            bail!("circular profile extension: {}", parent_name);
        }
        let parent = configs
            .0
            .get(parent_name)
            .with_context(|| format!("extended profile '{}' not found", parent_name))?;
        visited.push(parent_name.clone());
        expand_extend(configs, parent, visited)?
    } else {
        (Properties::new(), ProfileMeta::default())
    };

    // Child's explicit Some overrides parent; None falls back to parent's value.
    let meta = ProfileMeta {
        exec: profile.exec.clone().or(parent_meta.exec),
        debug: profile.debug.or(parent_meta.debug),
        confirm: profile.confirm.or(parent_meta.confirm),
    };
    merge_into(&mut base, profile.properties.clone())?;
    Ok((base, meta))
}

/// Merge `src` into `dst`.
///
/// In arrays, `"..."` is replaced by the parent's list at that position.
/// It may appear at most once; multiple occurrences are an error.
/// Arrays without `"..."` replace the parent's value entirely.
fn merge_into(dst: &mut Properties, src: Properties) -> Result<()> {
    let sentinel = Value::String("...".into());
    for (key, src_val) in src {
        if let Value::Array(src_arr) = src_val {
            let array = match src_arr.iter().filter(|v| *v == &sentinel).count() {
                0 => src_arr,
                1 => {
                    let base_items = match dst.get(&key) {
                        Some(Value::Array(arr)) => arr.clone(),
                        _ => vec![],
                    };
                    let mut merged = Vec::with_capacity(src_arr.len() - 1 + base_items.len());
                    for v in src_arr {
                        if v == sentinel {
                            merged.extend(base_items.iter().cloned());
                        } else {
                            merged.push(v);
                        }
                    }
                    merged
                }
                _ => anyhow::bail!("property '{key}': '...' may appear at most once"),
            };
            dst.insert(key, Value::Array(array));
        } else {
            dst.insert(key, src_val);
        }
    }
    Ok(())
}

fn build_args(
    properties: Properties,
    meta: ProfileMeta,
    match_log: Vec<String>,
) -> Result<ResolvedProfile> {
    let mut args: Vec<String> = Vec::new();

    for (key, val) in &properties {
        for str_val in value_to_strings(val)? {
            args.push("-p".into());
            args.push(format!("{key}={str_val}"));
        }
    }

    Ok(ResolvedProfile {
        systemd_args: args,
        exec: meta.exec,
        debug: meta.debug.unwrap_or(false),
        confirm: meta.confirm.unwrap_or(false),
        match_log,
    })
}

/// Convert a TOML value to one or more strings for systemd-run `-p` arguments.
/// Booleans become "yes"/"no".
fn value_to_strings(val: &Value) -> Result<Vec<String>> {
    match val {
        Value::String(s) => Ok(vec![expand_env(s)?]),
        Value::Boolean(b) => Ok(vec![if *b { "yes" } else { "no" }.to_string()]),
        Value::Integer(n) => Ok(vec![n.to_string()]),
        Value::Float(f) => Ok(vec![f.to_string()]),
        Value::Array(arr) => arr
            .iter()
            .map(value_to_strings)
            .collect::<Result<Vec<_>>>()
            .map(|v| v.into_iter().flatten().collect()),
        Value::Datetime(_) => anyhow::bail!("datetime is not a valid systemd property value"),
        Value::Table(_) => anyhow::bail!("table is not a valid systemd property value"),
    }
}

/// Expand `$VAR` and `${VAR}` using the current process environment.
/// Returns an error if a referenced variable is not set.
fn expand_env(s: &str) -> Result<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap());

    let mut result = String::with_capacity(s.len());
    let mut last_end = 0;

    for cap in re.captures_iter(s) {
        let m = cap.get(0).unwrap();
        result.push_str(&s[last_end..m.start()]);
        let name = cap.get(1).or(cap.get(2)).map(|m| m.as_str()).unwrap_or("");
        let val = std::env::var(name)
            .with_context(|| format!("undefined environment variable '${name}'"))?;
        result.push_str(&val);
        last_end = m.end();
    }

    result.push_str(&s[last_end..]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use glob::Pattern;

    use super::*;

    fn make_configs(profiles: Vec<(&str, ValidatedProfileConfig)>) -> ValidatedConfigMap {
        ValidatedConfigMap(
            profiles
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn profile(pattern: CommandPattern, props: Vec<(&str, Value)>) -> ValidatedProfileConfig {
        ValidatedProfileConfig {
            extend: None,
            exec: None,
            debug: None,
            confirm: None,
            pattern,
            properties: props.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        }
    }

    fn str(s: &str) -> Value {
        Value::String(s.into())
    }
    fn arr(items: &[&str]) -> Value {
        Value::Array(items.iter().map(|s| str(s)).collect())
    }
    fn has_arg(args: &[String], kv: &str) -> bool {
        args.windows(2).any(|w| w[0] == "-p" && w[1] == kv)
    }

    #[test]
    fn test_exact_match() {
        let configs = make_configs(vec![(
            "curl",
            profile(
                CommandPattern::Exact("curl".to_owned()),
                vec![("MemoryMax", str("1G"))],
            ),
        )]);
        let r = resolve(&configs, "curl").unwrap();
        assert!(has_arg(&r.systemd_args, "MemoryMax=1G"));
    }

    #[test]
    fn test_exact_no_match() {
        let configs = make_configs(vec![(
            "curl",
            profile(
                CommandPattern::Exact("curl".to_owned()),
                vec![("MemoryMax", str("1G"))],
            ),
        )]);
        let r = resolve(&configs, "wget").unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn test_glob_match() {
        let configs = make_configs(vec![(
            "browsers",
            profile(
                CommandPattern::Glob(Pattern::new("*browser*").unwrap()),
                vec![("PrivateNetwork", Value::Boolean(true))],
            ),
        )]);
        let r = resolve(&configs, "firefox-browser").unwrap();
        assert!(has_arg(&r.systemd_args, "PrivateNetwork=yes"));
    }

    #[test]
    fn test_never_skipped() {
        let configs = make_configs(vec![(
            "base",
            profile(CommandPattern::Never, vec![("CPUQuota", str("50%"))]),
        )]);
        let r = resolve(&configs, "base").unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn test_extend() {
        let base = profile(
            CommandPattern::Never,
            vec![("CPUQuota", str("50%")), ("ReadOnlyPaths", arr(&["/"]))],
        );
        let mut child = profile(
            CommandPattern::Exact("curl".to_owned()),
            vec![("ReadWritePaths", arr(&["/tmp"]))],
        );
        child.extend = Some("base".into());

        let configs = make_configs(vec![("base", base), ("curl", child)]);
        let r = resolve(&configs, "curl").unwrap();

        assert!(has_arg(&r.systemd_args, "CPUQuota=50%"));
        assert!(has_arg(&r.systemd_args, "ReadOnlyPaths=/"));
        assert!(has_arg(&r.systemd_args, "ReadWritePaths=/tmp"));
    }

    #[test]
    fn test_array_replaces_by_default() {
        let base = profile(
            CommandPattern::Never,
            vec![("ReadOnlyPaths", arr(&["/", "/etc"]))],
        );
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("ReadOnlyPaths", arr(&["/usr"]))],
        );
        child.extend = Some("base".into());

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app").unwrap();

        let paths: Vec<_> = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("ReadOnlyPaths="))
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(paths, ["ReadOnlyPaths=/usr"]);
    }

    #[test]
    fn test_array_extend_with_sentinel() {
        let base = profile(CommandPattern::Never, vec![("ReadOnlyPaths", arr(&["/"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("ReadOnlyPaths", arr(&["...", "/etc"]))],
        );
        child.extend = Some("base".into());

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app").unwrap();

        let paths: Vec<_> = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("ReadOnlyPaths="))
            .map(|w| w[1].as_str())
            .collect();
        assert!(paths.contains(&"ReadOnlyPaths=/"));
        assert!(paths.contains(&"ReadOnlyPaths=/etc"));
        assert!(!paths.iter().any(|p| p.contains("...")));
    }

    #[test]
    fn test_array_sentinel_in_middle() {
        let base = profile(CommandPattern::Never, vec![("Paths", arr(&["/base"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("Paths", arr(&["/before", "...", "/after"]))],
        );
        child.extend = Some("base".into());

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app").unwrap();

        let vals: Vec<_> = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("Paths="))
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(vals, ["Paths=/before", "Paths=/base", "Paths=/after"]);
    }

    #[test]
    fn test_array_duplicate_sentinel_errors() {
        let base = profile(CommandPattern::Never, vec![("Paths", arr(&["/base"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("Paths", arr(&["...", "/mid", "..."]))],
        );
        child.extend = Some("base".into());

        let configs = make_configs(vec![("base", base), ("app", child)]);
        assert!(resolve(&configs, "app").is_err());
    }

    #[test]
    fn test_exact_overrides_glob() {
        let glob_p = profile(
            CommandPattern::Glob(Pattern::new("cu*").unwrap()),
            vec![("MemoryMax", str("512M"))],
        );
        let exact_p = profile(
            CommandPattern::Exact("curl".to_owned()),
            vec![("MemoryMax", str("2G"))],
        );

        let configs = make_configs(vec![("glob_curl", glob_p), ("curl", exact_p)]);
        let r = resolve(&configs, "curl").unwrap();

        let last_mem = r
            .systemd_args
            .windows(2)
            .rfind(|w| w[0] == "-p" && w[1].starts_with("MemoryMax="))
            .map(|w| w[1].as_str());
        assert_eq!(last_mem, Some("MemoryMax=2G"));
    }

    #[test]
    fn test_expand_env() {
        unsafe { std::env::set_var("SCUDO_TEST_VAR", "hello") };
        assert_eq!(expand_env("$SCUDO_TEST_VAR/world").unwrap(), "hello/world");
        assert_eq!(
            expand_env("${SCUDO_TEST_VAR}/world").unwrap(),
            "hello/world"
        );
        assert_eq!(expand_env("/no/vars").unwrap(), "/no/vars");
        assert!(expand_env("$SCUDO_UNDEFINED_XYZ_VAR").is_err());
    }
}

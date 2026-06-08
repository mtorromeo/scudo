use std::{collections::HashMap, sync::OnceLock};

use anyhow::{Context as _, Result, bail};
use regex::Regex;
use toml::Value;

use crate::config::{ArgAliases, CommandPattern, ValidatedConfigMap, ValidatedProfileConfig};

#[derive(Debug)]
pub struct ResolvedProfile {
    pub systemd_args: Vec<String>,
    pub exec: Option<String>,
    pub debug: bool,
    pub confirm: bool,
    pub match_log: Vec<String>,
}

type Properties = HashMap<String, Value>;

/// Maps arg variable names to their accumulated values (always a `Vec`).
/// Positionals are stored as `"1"`, `"2"`, `"rest"` — without the `arg_` prefix.
/// Named flags are stored without the `arg_` prefix (e.g. `"foo_bar"` for `--foo-bar`).
type ArgVars = HashMap<String, Vec<String>>;

#[derive(Debug, Default)]
struct ProfileMeta {
    exec: Option<String>,
    debug: Option<bool>,
    confirm: Option<bool>,
    arg_aliases: ArgAliases,
    arg_flags: Vec<String>,
}

/// Collect all profiles that match `command`, merge them in priority order
/// (glob < regex < exact), and build the systemd-run argument list.
pub fn resolve(
    configs: &ValidatedConfigMap,
    command: &str,
    command_args: &[String],
) -> Result<ResolvedProfile> {
    let mut exact_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut glob_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut regex_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();

    let matches_cmd = |p: &CommandPattern| match p {
        CommandPattern::Exact(s) => s == command,
        CommandPattern::Glob(g) => g.matches(command),
        CommandPattern::Regex(r) => r.is_match(command),
        CommandPattern::Sentinel => false,
    };

    for (name, profile) in &configs.0 {
        let resolved = if profile.pattern.iter().any(|p| matches!(p, CommandPattern::Sentinel)) {
            resolve_patterns(configs, profile, &mut vec![])?
        } else {
            profile.pattern.clone()
        };
        if !resolved.iter().any(matches_cmd) {
            continue;
        }
        match resolved.iter().find(|p| !matches!(p, CommandPattern::Sentinel)) {
            Some(CommandPattern::Exact(_)) => exact_matches.push((name, profile)),
            Some(CommandPattern::Glob(_)) => glob_matches.push((name, profile)),
            Some(CommandPattern::Regex(_)) => regex_matches.push((name, profile)),
            _ => {}
        }
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

        let (props, m) = expand_extend(configs, profile, &mut Vec::new(), &mut match_log, 0)?;
        merge_into(&mut merged, props)?;
        meta.exec = m.exec.or(meta.exec);
        meta.debug = m.debug.or(meta.debug);
        meta.confirm = m.confirm.or(meta.confirm);
        meta.arg_aliases.extend(m.arg_aliases);
        meta.arg_flags.extend(m.arg_flags);
    }

    let arg_vars = parse_command_args(command_args, &meta.arg_aliases, &meta.arg_flags);
    build_args(&merged, meta, match_log, &arg_vars)
}

fn match_description(patterns: &[CommandPattern]) -> (&'static str, String) {
    let kind = match patterns.iter().find(|p| !matches!(p, CommandPattern::Sentinel)) {
        Some(CommandPattern::Exact(_)) => "exact",
        Some(CommandPattern::Glob(_)) => "glob",
        Some(CommandPattern::Regex(_)) => "regex",
        _ => "never",
    };
    let joined = patterns
        .iter()
        .filter_map(|p| match p {
            CommandPattern::Exact(s) => Some(s.as_str()),
            CommandPattern::Glob(g) => Some(g.as_str()),
            CommandPattern::Regex(r) => Some(r.as_str()),
            CommandPattern::Sentinel => None,
        })
        .collect::<Vec<_>>()
        .join("|");
    (kind, joined)
}

/// Resolve `CommandPattern::Sentinel` entries by splicing in the first parent's
/// resolved patterns. Returns a sentinel-free pattern list.
fn resolve_patterns(
    configs: &ValidatedConfigMap,
    profile: &ValidatedProfileConfig,
    visited: &mut Vec<String>,
) -> Result<Vec<CommandPattern>> {
    if !profile.pattern.iter().any(|p| matches!(p, CommandPattern::Sentinel)) {
        return Ok(profile.pattern.clone());
    }
    let parent_patterns = profile
        .extend
        .iter()
        .find_map(|parent_name| configs.0.get(parent_name.as_str()).map(|p| (parent_name, p)))
        .map(|(parent_name, parent)| {
            if visited.contains(parent_name) {
                bail!("circular pattern extension: {parent_name}");
            }
            visited.push(parent_name.clone());
            let result = resolve_patterns(configs, parent, visited);
            visited.pop();
            result
        })
        .transpose()?
        .unwrap_or_default();

    let mut result = Vec::new();
    for p in &profile.pattern {
        if matches!(p, CommandPattern::Sentinel) {
            result.extend(
                parent_patterns
                    .iter()
                    .filter(|p| !matches!(p, CommandPattern::Sentinel))
                    .cloned(),
            );
        } else {
            result.push(p.clone());
        }
    }
    Ok(result)
}

/// Recursively resolve `extend`, returning the fully-merged property map and
/// the metadata flags for this profile's chain.
///
/// Multiple parents are resolved left-to-right; later entries take precedence.
/// `visited` tracks the current resolution path for cycle detection; it is
/// push/popped per branch so that diamond inheritance (A → [B, C] where B and C
/// both extend D) works correctly.
fn expand_extend(
    configs: &ValidatedConfigMap,
    profile: &ValidatedProfileConfig,
    visited: &mut Vec<String>,
    log: &mut Vec<String>,
    depth: usize,
) -> Result<(Properties, ProfileMeta)> {
    let mut base = Properties::new();
    let mut base_meta = ProfileMeta::default();

    for parent_name in &profile.extend {
        if visited.contains(parent_name) {
            bail!("circular profile extension: {parent_name}");
        }
        let parent = configs
            .0
            .get(parent_name)
            .with_context(|| format!("extended profile '{parent_name}' not found"))?;

        let indent = " ".repeat(depth.saturating_mul(3).saturating_add(2));
        log.push(format!("{indent}└─ extends '{parent_name}'"));

        visited.push(parent_name.clone());
        let (parent_props, parent_meta) =
            expand_extend(configs, parent, visited, log, depth.saturating_add(1))?;
        visited.pop(); // restore so sibling branches can share the same parents

        merge_into(&mut base, parent_props)?;
        // Later parent (rightmost) wins for scalar meta fields.
        base_meta.exec = parent_meta.exec.or(base_meta.exec);
        base_meta.debug = parent_meta.debug.or(base_meta.debug);
        base_meta.confirm = parent_meta.confirm.or(base_meta.confirm);
        base_meta.arg_aliases.extend(parent_meta.arg_aliases);
        base_meta.arg_flags.extend(parent_meta.arg_flags);
    }

    // Current profile's values override everything inherited from parents.
    let mut merged_aliases = base_meta.arg_aliases;
    merged_aliases.extend(profile.arg_aliases.clone());
    let mut merged_flags = base_meta.arg_flags;
    merged_flags.extend(profile.arg_flags.iter().cloned());

    let meta = ProfileMeta {
        exec: profile.exec.clone().or(base_meta.exec),
        debug: profile.debug.or(base_meta.debug),
        confirm: profile.confirm.or(base_meta.confirm),
        arg_aliases: merged_aliases,
        arg_flags: merged_flags,
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
                    let mut merged = Vec::with_capacity(
                        src_arr
                            .len()
                            .saturating_sub(1)
                            .saturating_add(base_items.len()),
                    );
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

/// Parse `command_args` into a map of arg variable name → accumulated values.
///
/// - Flags in `aliases` (value flags): consume the next arg (or use `=val` form).
///   With `nargs = "+"`, consume all following non-flag args.
///   All occurrences are accumulated into the `Vec`.
/// - Flags in `bool_flags`: boolean, never consume the next arg.
/// - Undeclared `--long` flags: heuristic — consume next non-flag arg as value.
/// - Undeclared `-s` flags: conservative — boolean.
/// - `--` terminates option parsing; everything after is positional.
/// - Remaining args (not consumed as flag values) become `arg_1`, `arg_2`, …
///   and `arg_rest` (space-joined).
fn parse_command_args(args: &[String], aliases: &ArgAliases, bool_flags: &[String]) -> ArgVars {
    // Build reverse map: flag_string → (var_name, is_nargs_plus)
    let mut value_flags: HashMap<&str, (&str, bool)> = HashMap::new();
    for (var_name, decl) in aliases {
        let multi = decl.is_multi_value();
        for flag in decl.flags() {
            value_flags.insert(flag.as_str(), (var_name.as_str(), multi));
        }
    }
    let bool_flag_set: std::collections::HashSet<&str> =
        bool_flags.iter().map(String::as_str).collect();

    let mut vars: ArgVars = HashMap::new();
    let mut positional_index: usize = 0;
    let mut iter = args.iter().peekable();

    let push_positional = |vars: &mut ArgVars, idx: &mut usize, val: String| {
        *idx = idx.saturating_add(1);
        vars.entry(format!("{idx}")).or_default().push(val);
    };

    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') || arg == "-" {
            push_positional(&mut vars, &mut positional_index, arg.clone());
            continue;
        }

        if arg == "--" {
            // Everything after `--` is positional.
            for remaining in iter.by_ref() {
                push_positional(&mut vars, &mut positional_index, remaining.clone());
            }
            break;
        }

        // --opt=value or -s=value
        if let Some((flag, val)) = arg.split_once('=') {
            let var_name = if let Some((vn, _)) = value_flags.get(flag) {
                (*vn).to_owned()
            } else if let Some(derived) = auto_derive_var_name(flag) {
                derived
            } else {
                // short opt with '=' but undeclared — skip
                continue;
            };
            vars.entry(var_name).or_default().push(val.to_owned());
            continue;
        }

        // --opt or -s (no '=')
        if let Some((var_name, is_nargs_plus)) = value_flags.get(arg.as_str()).copied() {
            let var_name = var_name.to_owned();
            if is_nargs_plus {
                // Consume all following non-flag args.
                while iter
                    .peek()
                    .is_some_and(|a| !a.starts_with('-') && a.as_str() != "--")
                {
                    if let Some(val) = iter.next() {
                        vars.entry(var_name.clone()).or_default().push(val.clone());
                    }
                }
            } else if let Some(val) = iter.next() {
                vars.entry(var_name).or_default().push(val.clone());
            } else {
                // no value follows the flag — skip
            }
            continue;
        }

        if bool_flag_set.contains(arg.as_str()) {
            continue;
        }

        if arg.starts_with("--") {
            // Undeclared long option: heuristic — consume next non-flag arg as value.
            if let Some(var_name) = auto_derive_var_name(arg)
                && iter
                    .peek()
                    .is_some_and(|a| !a.starts_with('-') && a.as_str() != "--")
                && let Some(val) = iter.next()
            {
                vars.entry(var_name).or_default().push(val.clone());
            }
            // No value follows or underiviable flag — boolean, ignore.
        }

        // Undeclared short option: conservative boolean.
    }

    // Build rest from positionals.
    if positional_index > 0 {
        let rest: Vec<String> = (1..=positional_index)
            .filter_map(|n| vars.get(&format!("{n}")).and_then(|v| v.first()).cloned())
            .collect();
        if !rest.is_empty() {
            vars.insert("rest".to_owned(), vec![rest.join(" ")]);
        }
    }

    vars
}

/// Derive a variable name from a long option flag.
/// `--foo-bar` → `Some("foo_bar")`, short opts → `None`.
fn auto_derive_var_name(flag: &str) -> Option<String> {
    let stripped = flag.strip_prefix("--")?;
    Some(stripped.replace('-', "_"))
}

/// Make a path absolute relative to the process's current directory.
/// Uses `std::path::absolute` which normalises `.` components lexically
/// without requiring the path to exist.
fn make_absolute(path: &str) -> String {
    std::path::absolute(path).map_or_else(|_| path.to_owned(), |p| p.to_string_lossy().into_owned())
}

/// Returns `true` for systemd unit properties whose values are filesystem paths.
/// Variable expansions within these properties are automatically made absolute.
fn is_path_property(key: &str) -> bool {
    matches!(
        key,
        "ReadWritePaths"
            | "ReadOnlyPaths"
            | "InaccessiblePaths"
            | "ExecPaths"
            | "NoExecPaths"
            | "ExtensionDirectories"
            | "BindPaths"
            | "BindReadOnlyPaths"
            | "MountImages"
            | "ExtensionImages"
            | "TemporaryFileSystem"
            | "WorkingDirectory"
            | "RootDirectory"
            | "RootImage"
            | "RootVerity"
            | "EnvironmentFile"
            | "NetworkNamespacePath"
            | "UserNamespacePath"
            | "IPIngressFilterPath"
            | "IPEgressFilterPath"
            | "TTYPath"
            | "IODeviceWeight"
            | "IOReadBandwidthMax"
            | "IOWriteBandwidthMax"
            | "IOReadIOPSMax"
            | "IOWriteIOPSMax"
            | "IODeviceLatencyTargetSec"
            | "BlockIODeviceWeight"
            | "BlockIOReadBandwidth"
            | "BlockIOWriteBandwidth"
            | "DeviceAllow"
            | "BPFProgram"
    )
}

fn build_args(
    properties: &Properties,
    meta: ProfileMeta,
    match_log: Vec<String>,
    arg_vars: &ArgVars,
) -> Result<ResolvedProfile> {
    let mut args: Vec<String> = Vec::new();

    for (key, val) in properties {
        let path_prop = is_path_property(key);
        for str_val in value_to_strings(val, arg_vars, path_prop)? {
            args.push("-p".into());
            args.push(format_property(key, &str_val));
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

/// Format a `Key=value` property for systemd-run.
///
/// systemd parses path-list properties using space as a separator, so values
/// containing spaces must be wrapped in double quotes (C-style quoting).
fn format_property(key: &str, val: &str) -> String {
    if val.contains(' ') {
        let escaped = val.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{key}=\"{escaped}\"")
    } else {
        format!("{key}={val}")
    }
}

/// Convert a TOML value to one or more strings for systemd-run `-p` arguments.
/// Booleans become "yes"/"no".
/// Empty strings produced by missing `$arg_*` variables are filtered out from arrays.
/// When `is_path` is `true`, variable expansions are made absolute using the process's CWD.
fn value_to_strings(val: &Value, arg_vars: &ArgVars, is_path: bool) -> Result<Vec<String>> {
    match val {
        Value::String(s) => expand_vars(s, arg_vars, is_path),
        Value::Boolean(b) => Ok(vec![if *b { "yes" } else { "no" }.to_owned()]),
        Value::Integer(n) => Ok(vec![n.to_string()]),
        Value::Float(f) => Ok(vec![f.to_string()]),
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                for s in value_to_strings(item, arg_vars, is_path)? {
                    if !s.is_empty() {
                        result.push(s);
                    }
                }
            }
            Ok(result)
        }
        Value::Datetime(_) => anyhow::bail!("datetime is not a valid systemd property value"),
        Value::Table(_) => anyhow::bail!("table is not a valid systemd property value"),
    }
}

/// Expand `$VAR`, `${VAR}`, and `$arg_*` references in `s`.
///
/// - `$arg_name` / `${arg_name}` look up `name` in `arg_vars` (silently empty if absent).
///   If the variable holds N > 1 values, the template is replicated N times (one per value).
///   Having more than one multi-value `$arg_*` reference in the same template is an error.
/// - All other `$VAR` references are resolved from the environment; missing vars are an error.
/// - When `is_path` is `true`, every expanded variable value is made absolute using the
///   process's current directory. Only the variable expansion is canonicalized; literal
///   text in the template is left untouched.
///
/// Returns a `Vec<String>` (usually one element; N elements when an array arg causes explosion).
fn expand_vars(s: &str, arg_vars: &ArgVars, is_path: bool) -> Result<Vec<String>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").expect("regex is valid")
    });

    // We maintain a Vec of partially-built strings.
    // Most of the time this has exactly one element; it grows when an array arg is expanded.
    let mut results: Vec<String> = vec![String::new()];
    let mut last_end = 0;
    let mut array_var_seen = false;

    for cap in re.captures_iter(s) {
        let m = cap.get(0).expect("match should not fail");
        let literal = &s[last_end..m.start()];
        let name = cap.get(1).or(cap.get(2)).map_or("", |m| m.as_str());
        last_end = m.end();

        if let Some(arg_name) = name.strip_prefix("arg_") {
            let values = arg_vars.get(arg_name).cloned().unwrap_or_default();
            // Treat missing/empty arg var as a single empty-string expansion.
            let raw_vals: Vec<String> = if values.is_empty() {
                vec![String::new()]
            } else {
                values
            };
            // Canonicalize each non-empty value if this is a path property.
            let expand_vals: Vec<String> = if is_path {
                raw_vals
                    .into_iter()
                    .map(|v| if v.is_empty() { v } else { make_absolute(&v) })
                    .collect()
            } else {
                raw_vals
            };

            if expand_vals.len() > 1 {
                if array_var_seen {
                    bail!("string template '{s}' contains more than one array argument variable");
                }
                array_var_seen = true;
                // Explode: for each existing partial result × each value
                let mut new_results =
                    Vec::with_capacity(results.len().saturating_mul(expand_vals.len()));
                for existing in &results {
                    for val in &expand_vals {
                        let mut new = existing.clone();
                        new.push_str(literal);
                        new.push_str(val);
                        new_results.push(new);
                    }
                }
                results = new_results;
            } else {
                for r in &mut results {
                    r.push_str(literal);
                    r.push_str(expand_vals.first().map_or("", String::as_str));
                }
            }
        } else {
            let raw = std::env::var(name)
                .with_context(|| format!("undefined environment variable '${name}'"))?;
            let val = if is_path { make_absolute(&raw) } else { raw };
            for r in &mut results {
                r.push_str(literal);
                r.push_str(&val);
            }
        }
    }

    let suffix = &s[last_end..];
    for r in &mut results {
        r.push_str(suffix);
    }

    Ok(results)
}

/// Expand `$VAR` and `${VAR}` using the current process environment.
/// Returns an error if a referenced variable is not set.
/// Thin wrapper around `expand_vars` for use in tests and callers that don't need arg vars.
#[cfg(test)]
fn expand_env(s: &str) -> Result<String> {
    let mut results = expand_vars(s, &ArgVars::new(), false)?;
    Ok(results.pop().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use glob::Pattern;

    use super::*;
    use crate::config::ArgAliasDecl;

    fn make_configs(profiles: Vec<(&str, ValidatedProfileConfig)>) -> ValidatedConfigMap {
        ValidatedConfigMap(
            profiles
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }

    fn profile(pattern: CommandPattern, props: Vec<(&str, Value)>) -> ValidatedProfileConfig {
        ValidatedProfileConfig {
            extend: vec![],
            exec: None,
            debug: None,
            confirm: None,
            pattern: vec![pattern],
            arg_aliases: HashMap::new(),
            arg_flags: vec![],
            properties: props.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    fn never_profile(props: Vec<(&str, Value)>) -> ValidatedProfileConfig {
        ValidatedProfileConfig {
            pattern: vec![],
            extend: vec![],
            exec: None,
            debug: None,
            confirm: None,
            arg_aliases: HashMap::new(),
            arg_flags: vec![],
            properties: props.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    fn str(s: &str) -> Value {
        Value::String(s.into())
    }
    fn arr(items: &[&str]) -> Value {
        Value::Array(items.iter().map(|s| str(s)).collect())
    }
    #[expect(clippy::missing_asserts_for_indexing, clippy::indexing_slicing)]
    fn has_arg(args: &[String], kv: &str) -> bool {
        args.windows(2).any(|w| w[0] == "-p" && w[1] == kv)
    }

    #[test]
    fn exact_match() {
        let configs = make_configs(vec![(
            "curl",
            profile(
                CommandPattern::Exact("curl".to_owned()),
                vec![("MemoryMax", str("1G"))],
            ),
        )]);
        let r = resolve(&configs, "curl", &[]).unwrap();
        assert!(has_arg(&r.systemd_args, "MemoryMax=1G"));
    }

    #[test]
    fn exact_no_match() {
        let configs = make_configs(vec![(
            "curl",
            profile(
                CommandPattern::Exact("curl".to_owned()),
                vec![("MemoryMax", str("1G"))],
            ),
        )]);
        let r = resolve(&configs, "wget", &[]).unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn glob_match() {
        let configs = make_configs(vec![(
            "browsers",
            profile(
                CommandPattern::Glob(Pattern::new("*browser*").unwrap()),
                vec![("PrivateNetwork", Value::Boolean(true))],
            ),
        )]);
        let r = resolve(&configs, "firefox-browser", &[]).unwrap();
        assert!(has_arg(&r.systemd_args, "PrivateNetwork=yes"));
    }

    #[test]
    fn never_skipped() {
        let configs = make_configs(vec![(
            "base",
            never_profile(vec![("CPUQuota", str("50%"))]),
        )]);
        let r = resolve(&configs, "base", &[]).unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn extend() {
        let base = never_profile(vec![("CPUQuota", str("50%")), ("ReadOnlyPaths", arr(&["/"]))]);
        let mut child = profile(
            CommandPattern::Exact("curl".to_owned()),
            vec![("ReadWritePaths", arr(&["/tmp"]))],
        );
        child.extend = vec!["base".into()];

        let configs = make_configs(vec![("base", base), ("curl", child)]);
        let r = resolve(&configs, "curl", &[]).unwrap();

        assert!(has_arg(&r.systemd_args, "CPUQuota=50%"));
        assert!(has_arg(&r.systemd_args, "ReadOnlyPaths=/"));
        assert!(has_arg(&r.systemd_args, "ReadWritePaths=/tmp"));
    }

    #[test]
    #[expect(clippy::missing_asserts_for_indexing, clippy::indexing_slicing)]
    fn array_replaces_by_default() {
        let base = never_profile(vec![("ReadOnlyPaths", arr(&["/", "/etc"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("ReadOnlyPaths", arr(&["/usr"]))],
        );
        child.extend = vec!["base".into()];

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app", &[]).unwrap();

        let paths: Vec<_> = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("ReadOnlyPaths="))
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(paths, ["ReadOnlyPaths=/usr"]);
    }

    #[test]
    #[expect(clippy::missing_asserts_for_indexing, clippy::indexing_slicing)]
    fn array_extend_with_sentinel() {
        let base = never_profile(vec![("ReadOnlyPaths", arr(&["/"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("ReadOnlyPaths", arr(&["...", "/etc"]))],
        );
        child.extend = vec!["base".into()];

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app", &[]).unwrap();

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
    #[expect(clippy::missing_asserts_for_indexing, clippy::indexing_slicing)]
    fn array_sentinel_in_middle() {
        let base = never_profile(vec![("Paths", arr(&["/base"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("Paths", arr(&["/before", "...", "/after"]))],
        );
        child.extend = vec!["base".into()];

        let configs = make_configs(vec![("base", base), ("app", child)]);
        let r = resolve(&configs, "app", &[]).unwrap();

        let vals: Vec<_> = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("Paths="))
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(vals, ["Paths=/before", "Paths=/base", "Paths=/after"]);
    }

    #[test]
    fn array_duplicate_sentinel_errors() {
        let base = never_profile(vec![("Paths", arr(&["/base"]))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("Paths", arr(&["...", "/mid", "..."]))],
        );
        child.extend = vec!["base".into()];

        let configs = make_configs(vec![("base", base), ("app", child)]);
        resolve(&configs, "app", &[]).unwrap_err();
    }

    #[test]
    #[expect(clippy::missing_asserts_for_indexing, clippy::indexing_slicing)]
    fn exact_overrides_glob() {
        let glob_p = profile(
            CommandPattern::Glob(Pattern::new("cu*").unwrap()),
            vec![("MemoryMax", str("512M"))],
        );
        let exact_p = profile(
            CommandPattern::Exact("curl".to_owned()),
            vec![("MemoryMax", str("2G"))],
        );

        let configs = make_configs(vec![("glob_curl", glob_p), ("curl", exact_p)]);
        let r = resolve(&configs, "curl", &[]).unwrap();

        let last_mem = r
            .systemd_args
            .windows(2)
            .rfind(|w| w[0] == "-p" && w[1].starts_with("MemoryMax="))
            .map(|w| w[1].as_str());
        assert_eq!(last_mem, Some("MemoryMax=2G"));
    }

    #[test]
    fn path_with_spaces_is_quoted() {
        let configs = make_configs(vec![(
            "app",
            profile(
                CommandPattern::Exact("app".to_owned()),
                vec![("BindPaths", str("/home/user/My Documents"))],
            ),
        )]);
        let r = resolve(&configs, "app", &[]).unwrap();
        assert!(has_arg(
            &r.systemd_args,
            "BindPaths=\"/home/user/My Documents\""
        ));
    }

    #[test]
    fn expand_var() {
        // SAFETY: Setting an environment variable is safe here as it is only used for testing.
        unsafe { std::env::set_var("SCUDO_TEST_VAR", "hello") }
        assert_eq!(expand_env("$SCUDO_TEST_VAR/world").unwrap(), "hello/world");
        assert_eq!(
            expand_env("${SCUDO_TEST_VAR}/world").unwrap(),
            "hello/world"
        );
        assert_eq!(expand_env("/no/vars").unwrap(), "/no/vars");
        expand_env("$SCUDO_UNDEFINED_XYZ_VAR").unwrap_err();
    }

    // ── arg variable tests ────────────────────────────────────────────────────

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arg_long_auto_detect_space() {
        let vars = parse_command_args(&args(&["--foo-bar", "val"]), &HashMap::new(), &[]);
        assert_eq!(vars.get("foo_bar"), Some(&vec!["val".to_owned()]));
    }

    #[test]
    fn arg_long_auto_detect_equals() {
        let vars = parse_command_args(&args(&["--foo-bar=val"]), &HashMap::new(), &[]);
        assert_eq!(vars.get("foo_bar"), Some(&vec!["val".to_owned()]));
    }

    #[test]
    fn arg_short_alias() {
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "target_directory".to_owned(),
            ArgAliasDecl::Simple(vec!["-t".to_owned(), "--target-directory".to_owned()]),
        );
        let vars = parse_command_args(&args(&["-t", "my-dir"]), &aliases, &[]);
        assert_eq!(
            vars.get("target_directory"),
            Some(&vec!["my-dir".to_owned()])
        );
    }

    #[test]
    fn arg_repeated_flag() {
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "include".to_owned(),
            ArgAliasDecl::Simple(vec!["--include".to_owned()]),
        );
        let vars = parse_command_args(&args(&["--include", "a", "--include", "b"]), &aliases, &[]);
        assert_eq!(
            vars.get("include"),
            Some(&vec!["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn arg_nargs_plus() {
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "include".to_owned(),
            ArgAliasDecl::Extended {
                flags: vec!["--include".to_owned()],
                nargs: Some("+".to_owned()),
            },
        );
        let vars = parse_command_args(&args(&["--include", "a", "b", "c"]), &aliases, &[]);
        assert_eq!(
            vars.get("include"),
            Some(&vec!["a".to_owned(), "b".to_owned(), "c".to_owned()])
        );
    }

    #[test]
    fn arg_missing_silent_filtered_from_array() {
        let configs = make_configs(vec![(
            "app",
            profile(
                CommandPattern::Exact("app".to_owned()),
                vec![("BindPaths", arr(&["/always", "$arg_optional"]))],
            ),
        )]);
        let r = resolve(&configs, "app", &[]).unwrap();
        // $arg_optional not set → empty → filtered; only /always remains
        assert!(has_arg(&r.systemd_args, "BindPaths=/always"));
        let count = r
            .systemd_args
            .windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with("BindPaths="))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn arg_template_explosion() {
        // Array arg variable in BindPaths explodes to one entry per value.
        // Use absolute paths so canonicalization doesn't alter the values.
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "inc".to_owned(),
            ArgAliasDecl::Simple(vec!["--inc".to_owned()]),
        );
        let mut p = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("BindPaths", arr(&["$arg_inc"]))],
        );
        p.arg_aliases = aliases;
        let configs = make_configs(vec![("app", p)]);
        let r = resolve(&configs, "app", &args(&["--inc", "/a", "--inc", "/b"])).unwrap();
        assert!(has_arg(&r.systemd_args, "BindPaths=/a"));
        assert!(has_arg(&r.systemd_args, "BindPaths=/b"));
    }

    #[test]
    fn arg_two_array_vars_in_string_errors() {
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "a".to_owned(),
            ArgAliasDecl::Simple(vec!["--aa".to_owned()]),
        );
        aliases.insert(
            "b".to_owned(),
            ArgAliasDecl::Simple(vec!["--bb".to_owned()]),
        );
        let mut p = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("BindPaths", str("$arg_a/$arg_b"))],
        );
        p.arg_aliases = aliases;
        let configs = make_configs(vec![("app", p)]);
        // Both --aa and --bb have 2 values each → error
        let result = resolve(
            &configs,
            "app",
            &args(&["--aa", "x", "--aa", "y", "--bb", "1", "--bb", "2"]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn arg_positional_simple() {
        let vars = parse_command_args(&args(&["my-dir"]), &HashMap::new(), &[]);
        assert_eq!(vars.get("1"), Some(&vec!["my-dir".to_owned()]));
    }

    #[test]
    fn arg_positional_with_bool_flag() {
        let vars = parse_command_args(&args(&["-p", "my-dir"]), &HashMap::new(), &args(&["-p"]));
        assert_eq!(vars.get("1"), Some(&vec!["my-dir".to_owned()]));
        assert!(!vars.contains_key("p"));
    }

    #[test]
    fn arg_positional_with_value_flag() {
        let mut aliases: ArgAliases = HashMap::new();
        aliases.insert(
            "target_directory".to_owned(),
            ArgAliasDecl::Simple(vec!["-t".to_owned()]),
        );
        let vars = parse_command_args(&args(&["-t", "dir", "file1"]), &aliases, &[]);
        assert_eq!(vars.get("target_directory"), Some(&vec!["dir".to_owned()]));
        assert_eq!(vars.get("1"), Some(&vec!["file1".to_owned()]));
    }

    #[test]
    fn arg_rest() {
        let vars = parse_command_args(
            &args(&["-p", "dir1", "dir2"]),
            &HashMap::new(),
            &args(&["-p"]),
        );
        assert_eq!(vars.get("1"), Some(&vec!["dir1".to_owned()]));
        assert_eq!(vars.get("2"), Some(&vec!["dir2".to_owned()]));
        assert_eq!(vars.get("rest"), Some(&vec!["dir1 dir2".to_owned()]));
    }

    #[test]
    fn arg_double_dash() {
        let vars = parse_command_args(
            &args(&["--", "--not-a-flag", "positional"]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(vars.get("1"), Some(&vec!["--not-a-flag".to_owned()]));
        assert_eq!(vars.get("2"), Some(&vec!["positional".to_owned()]));
        assert!(!vars.contains_key("not_a_flag"));
    }

    // ── path canonicalization tests ───────────────────────────────────────────

    /// Build a profile whose single property is a path property using a $VAR reference.
    fn path_profile(key: &str, template: &str) -> ValidatedConfigMap {
        make_configs(vec![(
            "app",
            profile(
                CommandPattern::Exact("app".to_owned()),
                vec![(key, str(template))],
            ),
        )])
    }

    #[test]
    fn path_env_var_relative_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_PATH", "relative/dir") }
        let configs = path_profile("BindPaths", "$SCUDO_TEST_PATH");
        let r = resolve(&configs, "app", &[]).unwrap();
        let expected = cwd.join("relative/dir").to_string_lossy().into_owned();
        assert!(has_arg(&r.systemd_args, &format!("BindPaths={expected}")));
    }

    #[test]
    fn path_env_var_absolute_unchanged() {
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_ABS_PATH", "/already/absolute") }
        let configs = path_profile("BindPaths", "$SCUDO_TEST_ABS_PATH");
        let r = resolve(&configs, "app", &[]).unwrap();
        assert!(has_arg(&r.systemd_args, "BindPaths=/already/absolute"));
    }

    #[test]
    fn path_var_non_path_property_not_canonicalized() {
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_NONPATH", "relative/value") }
        let configs = path_profile("CPUQuota", "$SCUDO_TEST_NONPATH");
        let r = resolve(&configs, "app", &[]).unwrap();
        // CPUQuota is not a path property — value should be unchanged
        assert!(has_arg(&r.systemd_args, "CPUQuota=relative/value"));
    }

    #[test]
    fn path_arg_relative_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let p = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("BindPaths", str("$arg_1"))],
        );
        let configs = make_configs(vec![("app", p)]);
        let r = resolve(&configs, "app", &args(&["mydir"])).unwrap();
        let expected = cwd.join("mydir").to_string_lossy().into_owned();
        assert!(has_arg(&r.systemd_args, &format!("BindPaths={expected}")));
    }

    #[test]
    fn path_literal_not_touched() {
        // Hardcoded relative string (no variable) — not canonicalized
        let configs = path_profile("BindPaths", "relative/hardcoded");
        let r = resolve(&configs, "app", &[]).unwrap();
        assert!(has_arg(&r.systemd_args, "BindPaths=relative/hardcoded"));
    }

    #[test]
    fn path_literal_prefix_with_var_relative() {
        // The `-` prefix is literal; the variable value is canonicalized
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_DASH_PATH", "some/dir") }
        let configs = path_profile("ReadWritePaths", "-$SCUDO_TEST_DASH_PATH");
        let r = resolve(&configs, "app", &[]).unwrap();
        let expected = format!("-{}", cwd.join("some/dir").to_string_lossy());
        assert!(has_arg(
            &r.systemd_args,
            &format!("ReadWritePaths={expected}")
        ));
    }

    // ── multi-extend tests ────────────────────────────────────────────────────

    #[test]
    fn multi_extend_priority() {
        // extend = ["a", "b"]: b overrides a; current profile overrides b.
        let a = never_profile(vec![("CPUQuota", str("10%")), ("MemoryMax", str("128M"))]);
        let b = never_profile(vec![("CPUQuota", str("20%")), ("MemoryHigh", str("256M"))]);
        let mut child = profile(
            CommandPattern::Exact("app".to_owned()),
            vec![("CPUQuota", str("50%"))],
        );
        child.extend = vec!["a".into(), "b".into()];

        let configs = make_configs(vec![("a", a), ("b", b), ("app", child)]);
        let r = resolve(&configs, "app", &[]).unwrap();

        // child wins for CPUQuota
        assert!(has_arg(&r.systemd_args, "CPUQuota=50%"));
        // b wins over a for CPUQuota (but child wins overall)
        // MemoryMax from a is present (b didn't override it)
        assert!(has_arg(&r.systemd_args, "MemoryMax=128M"));
        // MemoryHigh from b is present
        assert!(has_arg(&r.systemd_args, "MemoryHigh=256M"));
    }

    #[test]
    fn multi_extend_diamond() {
        // A extends [B, C]; B and C both extend D.
        // Diamond inheritance must not cause a circular-extend error.
        let d = never_profile(vec![("MemoryMax", str("64M"))]);
        let mut b = never_profile(vec![("CPUQuota", str("10%"))]);
        b.extend = vec!["d".into()];
        let mut c = never_profile(vec![("CPUQuota", str("20%"))]);
        c.extend = vec!["d".into()];
        let mut a = profile(CommandPattern::Exact("app".to_owned()), vec![]);
        a.extend = vec!["b".into(), "c".into()];

        let configs = make_configs(vec![("d", d), ("b", b), ("c", c), ("app", a)]);
        let r = resolve(&configs, "app", &[]).unwrap();

        // D's property visible; no error
        assert!(has_arg(&r.systemd_args, "MemoryMax=64M"));
        // C (rightmost) wins over B for CPUQuota
        assert!(has_arg(&r.systemd_args, "CPUQuota=20%"));
    }

    #[test]
    fn extend_circular_still_detected() {
        let mut a = never_profile(vec![]);
        a.extend = vec!["b".into()];
        let mut b = never_profile(vec![]);
        b.extend = vec!["a".into()];
        let mut child = profile(CommandPattern::Exact("app".to_owned()), vec![]);
        child.extend = vec!["a".into()];

        let configs = make_configs(vec![("a", a), ("b", b), ("app", child)]);
        assert!(resolve(&configs, "app", &[]).is_err());
    }
}

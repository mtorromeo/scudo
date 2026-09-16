use std::{collections::HashMap, sync::OnceLock};

use anyhow::{Context as _, Result, bail};
use regex::Regex;
use toml::Value;

use crate::{
    config::{ArgAliases, CommandPattern, MatchTarget, ValidatedConfigMap, ValidatedProfileConfig},
    logging::{Level, LogConfig},
    policy::{FilesystemConfig, FilesystemPolicy, NetworkConfig, NetworkPolicy, Policy},
};

#[derive(Debug)]
pub struct ResolvedProfile {
    pub systemd_args: Vec<String>,
    pub exec: Option<String>,
    /// Level and destination for scudo's own output, still without the command
    /// line's say: the caller layers that on top.
    pub log: LogConfig,
    pub confirm: bool,
    pub match_log: Vec<String>,
    /// Policies to hand to `scudo-bpfd` before the command starts.
    pub policies: Vec<Policy>,
}

type Properties = HashMap<String, Value>;

/// Maps arg variable names to their accumulated values (always a `Vec`).
/// Positionals are stored as `"1"`, `"2"`, `"rest"` — without the `arg_` prefix.
/// Named flags are stored without the `arg_` prefix (e.g. `"foo_bar"` for `--foo-bar`).
type ArgVars = HashMap<String, Vec<String>>;

#[derive(Debug, Default)]
struct ProfileMeta {
    exec: Option<String>,
    verbose: Option<bool>,
    confirm: Option<bool>,
    arg_aliases: ArgAliases,
    arg_flags: Vec<String>,
    filesystem: FilesystemConfig,
    /// Raw network policy, still in TOML form so that it merges with the same
    /// array semantics as every other property.
    network: Option<Properties>,
    log: LogConfig,
}

/// Options controlling which profiles [`resolve_with`] applies.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResolveOptions<'a> {
    /// Profiles selected explicitly on the command line. They are applied after any
    /// matched profiles, so they take precedence; order is significant (later wins).
    pub profiles: &'a [String],
    /// Skip pattern matching entirely; only `profiles` are applied.
    pub no_match: bool,
}

/// Collect all profiles that match `command`, merge them in priority order
/// (glob < regex < exact), and build the systemd-run argument list.
pub fn resolve(
    configs: &ValidatedConfigMap,
    command: &str,
    command_args: &[String],
) -> Result<ResolvedProfile> {
    resolve_with(configs, command, command_args, ResolveOptions::default())
}

/// Like [`resolve`], but honouring explicit profile selection from the command line.
///
/// Explicitly selected profiles are appended after the matched ones, so they override
/// them. A profile that both matches and is selected explicitly is applied only once,
/// in its explicit position.
pub fn resolve_with(
    configs: &ValidatedConfigMap,
    command: &str,
    command_args: &[String],
    opts: ResolveOptions<'_>,
) -> Result<ResolvedProfile> {
    // Resolved first so an unknown name fails before anything else happens.
    let selected = select_profiles(configs, opts.profiles)?;

    let mut exact_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut glob_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    let mut regex_matches: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();

    if !opts.no_match {
        let full_command: String = core::iter::once(command)
            .chain(command_args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");

        let matches_cmd = |p: &CommandPattern| {
            let subject = |t: &MatchTarget| match t {
                MatchTarget::Command => command,
                MatchTarget::FullCommand => full_command.as_str(),
            };
            match p {
                CommandPattern::Exact(s, t) => s == subject(t),
                CommandPattern::Glob(g, t) => g.matches(subject(t)),
                CommandPattern::Regex(r, t) => r.is_match(subject(t)),
                CommandPattern::Sentinel => false,
            }
        };

        for (name, profile) in &configs.0 {
            // Already selected explicitly — applied later, in its explicit position.
            if selected.iter().any(|(n, _)| *n == name.as_str()) {
                continue;
            }
            let resolved = if profile
                .pattern
                .iter()
                .any(|p| matches!(p, CommandPattern::Sentinel))
            {
                resolve_patterns(configs, profile, &mut vec![])?
            } else {
                profile.pattern.clone()
            };
            // A profile without `match` has no patterns and matches nothing:
            // the normal shape of a base profile, reachable only via
            // `extend`/`--profile`.
            match matching_pattern(&resolved, matches_cmd) {
                Some(CommandPattern::Exact(_, _)) => exact_matches.push((name, profile)),
                Some(CommandPattern::Glob(_, _)) => glob_matches.push((name, profile)),
                Some(CommandPattern::Regex(_, _)) => regex_matches.push((name, profile)),
                Some(CommandPattern::Sentinel) | None => {}
            }
        }
    }

    let mut match_log: Vec<String> = Vec::new();
    let mut merged = Properties::new();
    let mut meta = ProfileMeta::default();

    let chain = glob_matches
        .iter()
        .map(|entry| (entry, Some("glob")))
        .chain(regex_matches.iter().map(|entry| (entry, Some("regex"))))
        .chain(exact_matches.iter().map(|entry| (entry, Some("exact"))))
        .chain(selected.iter().map(|entry| (entry, None)));

    for ((name, profile), kind) in chain {
        if let Some(kind) = kind {
            let pattern = match_description(&profile.pattern);
            match_log.push(format!("profile '{name}' matched {kind} '{pattern}'"));
        } else {
            match_log.push(format!("profile '{name}' selected explicitly"));
        }

        let (props, m) = expand_extend(configs, profile, &mut Vec::new(), &mut match_log, 0)?;
        merge_into(&mut merged, props)?;
        meta.exec = m.exec.or(meta.exec);
        meta.verbose = m.verbose.or(meta.verbose);
        meta.confirm = m.confirm.or(meta.confirm);
        meta.arg_aliases.extend(m.arg_aliases);
        meta.arg_flags.extend(m.arg_flags);
        merge_network(&mut meta.network, m.network)?;
        meta.log = m.log.over(meta.log);
        meta.filesystem = m.filesystem.over(meta.filesystem);
    }

    let arg_vars = parse_command_args(command_args, &meta.arg_aliases, &meta.arg_flags);
    build_args(&merged, meta, match_log, &arg_vars)
}

/// Look up explicitly requested profile names, preserving order and dropping duplicates.
///
/// An unknown name is an error: silently ignoring it would run the command with less
/// sandboxing than the user asked for. Synthetic keys created by cross-file self-extend
/// (see `config::load_configs`) contain a NUL and are deliberately not selectable.
fn select_profiles<'a>(
    configs: &'a ValidatedConfigMap,
    names: &[String],
) -> Result<Vec<(&'a str, &'a ValidatedProfileConfig)>> {
    let mut selected: Vec<(&str, &ValidatedProfileConfig)> = Vec::new();
    for name in names {
        if selected.iter().any(|(n, _)| *n == name.as_str()) {
            continue;
        }
        let (key, profile) = configs
            .0
            .get_key_value(name.as_str())
            .filter(|(key, _)| !key.contains('\0'))
            .with_context(|| format!("profile '{name}' not found"))?;
        selected.push((key.as_str(), profile));
    }
    Ok(selected)
}

/// Whether a profile's (sentinel-free) patterns match, and if so the pattern
/// that decides its specificity tier.
///
/// Command-name patterns are alternatives: one matching is enough, and it is the
/// one that sets the tier. Full-command patterns are extra conditions that must
/// all hold; they set the tier only when there is no command-name pattern. A
/// profile with no patterns at all never matches.
fn matching_pattern(
    patterns: &[CommandPattern],
    matches: impl Fn(&CommandPattern) -> bool,
) -> Option<&CommandPattern> {
    let targeting = |target| patterns.iter().filter(move |p| p.target() == Some(target));
    let mut full = targeting(MatchTarget::FullCommand);
    if !full.all(&matches) {
        return None;
    }
    let mut command = targeting(MatchTarget::Command).peekable();
    if command.peek().is_some() {
        command.find(|p| matches(p))
    } else {
        targeting(MatchTarget::FullCommand).next()
    }
}

fn match_description(patterns: &[CommandPattern]) -> String {
    patterns
        .iter()
        .filter_map(|p| match p {
            CommandPattern::Exact(s, _) => Some(s.as_str()),
            CommandPattern::Glob(g, _) => Some(g.as_str()),
            CommandPattern::Regex(r, _) => Some(r.as_str()),
            CommandPattern::Sentinel => None,
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// Resolve `CommandPattern::Sentinel` entries by splicing in the first parent's
/// resolved patterns. Returns a sentinel-free pattern list.
fn resolve_patterns(
    configs: &ValidatedConfigMap,
    profile: &ValidatedProfileConfig,
    visited: &mut Vec<String>,
) -> Result<Vec<CommandPattern>> {
    if !profile
        .pattern
        .iter()
        .any(|p| matches!(p, CommandPattern::Sentinel))
    {
        return Ok(profile.pattern.clone());
    }
    let parent_patterns = profile
        .extend
        .iter()
        .find_map(|parent_name| {
            configs
                .0
                .get(parent_name.as_str())
                .map(|parent| (parent_name, parent))
        })
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
        base_meta.verbose = parent_meta.verbose.or(base_meta.verbose);
        base_meta.confirm = parent_meta.confirm.or(base_meta.confirm);
        base_meta.arg_aliases.extend(parent_meta.arg_aliases);
        base_meta.arg_flags.extend(parent_meta.arg_flags);
        merge_network(&mut base_meta.network, parent_meta.network)?;
        base_meta.log = parent_meta.log.over(base_meta.log);
        base_meta.filesystem = parent_meta.filesystem.over(base_meta.filesystem);
    }

    // Current profile's values override everything inherited from parents.
    let mut merged_aliases = base_meta.arg_aliases;
    merged_aliases.extend(profile.arg_aliases.clone());
    let mut merged_flags = base_meta.arg_flags;
    merged_flags.extend(profile.arg_flags.iter().cloned());

    let mut network = base_meta.network;
    merge_network(
        &mut network,
        profile.network.clone().map(table_to_properties),
    )?;

    let meta = ProfileMeta {
        exec: profile.exec.clone().or(base_meta.exec),
        verbose: profile.verbose.or(base_meta.verbose),
        confirm: profile.confirm.or(base_meta.confirm),
        arg_aliases: merged_aliases,
        arg_flags: merged_flags,
        network,
        log: profile.log.clone().over(base_meta.log),
        filesystem: profile.filesystem.over(base_meta.filesystem),
    };
    merge_into(&mut base, profile.properties.clone())?;
    Ok((base, meta))
}

fn table_to_properties(table: toml::Table) -> Properties {
    table.into_iter().collect()
}

/// Merge a network policy table into the inherited one, reusing the same array
/// semantics as regular properties so that `"..."` splices the inherited list in.
///
/// Unlike `merge_into` this descends into nested tables, because the network
/// table has them: `dest` and `ports` each hold their own `allow` and `deny`
/// lists. Replacing one of those wholesale would drop the half the child did not
/// mention, and a `"..."` inside it would find no inherited list to splice.
fn merge_network(dst: &mut Option<Properties>, src: Option<Properties>) -> Result<()> {
    let Some(src) = src else {
        return Ok(());
    };
    let mut base: toml::Table = dst.take().unwrap_or_default().into_iter().collect();
    merge_table_into(&mut base, src.into_iter().collect())?;
    *dst = Some(base.into_iter().collect());
    Ok(())
}

/// `merge_into` for a `toml::Table`, descending into nested tables.
fn merge_table_into(dst: &mut toml::Table, src: toml::Table) -> Result<()> {
    for (key, src_val) in src {
        match src_val {
            Value::Array(src_arr) => {
                let merged = splice_array(dst.get(&key), src_arr, &key)?;
                dst.insert(key, Value::Array(merged));
            }
            Value::Table(src_tbl) => {
                let merged = match dst.remove(&key) {
                    Some(Value::Table(mut base)) => {
                        merge_table_into(&mut base, src_tbl)?;
                        base
                    }
                    _ => src_tbl,
                };
                dst.insert(key, Value::Table(merged));
            }
            other @ (Value::String(_)
            | Value::Integer(_)
            | Value::Float(_)
            | Value::Boolean(_)
            | Value::Datetime(_)) => {
                dst.insert(key, other);
            }
        }
    }
    Ok(())
}

/// Merge `src` into `dst`.
///
/// In arrays, `"..."` is replaced by the parent's list at that position.
/// It may appear at most once; multiple occurrences are an error.
/// Arrays without `"..."` replace the parent's value entirely.
fn merge_into(dst: &mut Properties, src: Properties) -> Result<()> {
    for (key, src_val) in src {
        let merged = match src_val {
            Value::Array(src_arr) => Value::Array(splice_array(dst.get(&key), src_arr, &key)?),
            other @ (Value::String(_)
            | Value::Integer(_)
            | Value::Float(_)
            | Value::Boolean(_)
            | Value::Datetime(_)
            | Value::Table(_)) => other,
        };
        dst.insert(key, merged);
    }
    Ok(())
}

/// Resolve `"..."` inside a child's array against the list it inherited.
fn splice_array(base: Option<&Value>, src_arr: Vec<Value>, key: &str) -> Result<Vec<Value>> {
    let sentinel = Value::String("...".into());
    match src_arr.iter().filter(|v| *v == &sentinel).count() {
        0 => Ok(src_arr),
        1 => {
            let base_items: &[Value] = match base {
                Some(Value::Array(arr)) => arr,
                _ => &[],
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
            Ok(merged)
        }
        _ => anyhow::bail!("property '{key}': '...' may appear at most once"),
    }
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
    let mut args = Vec::new();

    for (key, val) in properties {
        let path_prop = is_path_property(key);
        for str_val in value_to_strings(val, arg_vars, path_prop)? {
            args.push("-p".into());
            args.push(format_property(key, &str_val));
        }
    }

    // The properties a policy needs are added by `policy::apply`, once it knows
    // the policy is actually being enforced: emitting them for a policy that
    // ends up degraded would restrict the command for no benefit.
    let policies = build_policies(meta.network, meta.filesystem, arg_vars)?;

    let mut log = meta.log;
    // `verbose` predates the log table and asks for the same thing in fewer
    // words. A level written out says more than the boolean can, so it wins.
    if meta.verbose == Some(true) && log.level.is_none() {
        log.level = Some(Level::Debug);
    }
    if let Some(path) = log.path {
        log.path = Some(expand_env(&path)?);
    }

    Ok(ResolvedProfile {
        systemd_args: args,
        exec: meta.exec,
        log,
        confirm: meta.confirm.unwrap_or(false),
        match_log,
        policies,
    })
}

/// Turn the merged sub-tables into normalised policies.
///
/// A profile that asked for neither produces none, and the command is then
/// never registered with the daemon at all.
fn build_policies(
    network: Option<Properties>,
    filesystem: FilesystemConfig,
    arg_vars: &ArgVars,
) -> Result<Vec<Policy>> {
    let mut policies = Vec::new();

    if let Some(network) = network {
        let mut table = toml::Table::new();
        for (key, val) in network {
            if let Some(expanded) = expand_network_value(val, arg_vars, false)? {
                table.insert(key, expanded);
            }
        }

        let config: NetworkConfig = toml::Value::Table(table)
            .try_into()
            .context("invalid network policy")?;
        let policy = NetworkPolicy::try_from(config).context("invalid network policy")?;
        if !policy.is_unrestricted() {
            policies.push(Policy::Network(policy));
        }
    }

    // A table that said nothing is not a policy that says off: leaving it out
    // is what lets `--tui` fill the gap with one of its own.
    if !filesystem.is_empty() {
        policies.push(Policy::Filesystem(FilesystemPolicy::from(filesystem)));
    }
    Ok(policies)
}

/// Expand `$VAR` and `$arg_*` references inside a network policy value.
///
/// Mirrors `value_to_strings`: a multi-valued `$arg_*` replicates the list
/// element it appears in, and an element expanding to nothing is dropped.
/// Anywhere but a list there is nothing to replicate, so a multi-valued
/// expansion is an error rather than a silent truncation.
fn expand_network_value(val: Value, arg_vars: &ArgVars, in_list: bool) -> Result<Option<Value>> {
    match val {
        Value::String(s) => {
            let mut expanded = expand_vars(&s, arg_vars, false)?;
            expanded.retain(|e| !e.is_empty());
            match expanded.len() {
                0 => Ok(None),
                1 => Ok(expanded.pop().map(Value::String)),
                _ if in_list => Ok(Some(Value::Array(
                    expanded.into_iter().map(Value::String).collect(),
                ))),
                _ => bail!("network policy: '{s}' expands to multiple values outside a list"),
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match expand_network_value(item, arg_vars, true)? {
                    // A list element that itself expanded to a list is spliced in.
                    Some(Value::Array(nested)) => out.extend(nested),
                    Some(value) => out.push(value),
                    None => {}
                }
            }
            Ok(Some(Value::Array(out)))
        }
        Value::Table(items) => {
            let mut out = toml::Table::new();
            for (key, item) in items {
                // Every list in the network table is written as one — `allow`,
                // `deny` — so a table value is never itself a list context.
                if let Some(value) = expand_network_value(item, arg_vars, false)? {
                    out.insert(key, value);
                }
            }
            Ok(Some(Value::Table(out)))
        }
        other @ (Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_)) => {
            Ok(Some(other))
        }
    }
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
/// Thin wrapper around `expand_vars` for callers that don't need arg vars.
fn expand_env(s: &str) -> Result<String> {
    let mut results = expand_vars(s, &ArgVars::new(), false)?;
    Ok(results.pop().unwrap_or_default())
}

#[cfg(test)]
#[expect(clippy::indexing_slicing)]
mod tests {
    use glob::Pattern;

    use super::*;
    use crate::{
        config::ArgAliasDecl,
        logging::Target,
        policy::network::{
            Action, Destination, LogLevel, OnUnavailable, PortRange, PortRule, Protocol,
        },
    };

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
            verbose: None,
            confirm: None,
            pattern: vec![pattern],
            arg_aliases: HashMap::new(),
            arg_flags: vec![],
            network: None,
            filesystem: FilesystemConfig::default(),
            log: LogConfig::default(),
            properties: props.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    fn never_profile(props: Vec<(&str, Value)>) -> ValidatedProfileConfig {
        ValidatedProfileConfig {
            pattern: vec![],
            extend: vec![],
            exec: None,
            verbose: None,
            confirm: None,
            arg_aliases: HashMap::new(),
            arg_flags: vec![],
            network: None,
            filesystem: FilesystemConfig::default(),
            log: LogConfig::default(),
            properties: props.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    /// Build a config map through the real load pipeline, so that these tests
    /// exercise validation as well as merging.
    fn configs_from_toml(src: &str) -> ValidatedConfigMap {
        let raw: crate::config::ConfigMap = toml::from_str(src).unwrap();
        raw.try_into().unwrap()
    }

    fn resolved_policy(src: &str, command: &str, args: &[&str]) -> NetworkPolicy {
        let configs = configs_from_toml(src);
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let resolved = resolve(&configs, command, &args).unwrap();
        resolved
            .policies
            .into_iter()
            .find_map(|policy| match policy {
                Policy::Network(network) => Some(network),
                Policy::Filesystem(_) => None,
            })
            .expect("expected a network policy")
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
                CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
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
                CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
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
                CommandPattern::Glob(Pattern::new("*browser*").unwrap(), MatchTarget::Command),
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

    /// End-to-end through the config pipeline: the section name is an identifier,
    /// not a pattern, so a profile without `match` is invisible to the matcher —
    /// but still reachable by name.
    #[test]
    fn profile_without_match_is_only_reachable_by_name() {
        let configs = configs_from_toml(
            r#"
            [curl]
            systemd.CPUQuota = "50%"
            "#,
        );
        let r = resolve(&configs, "curl", &[]).unwrap();
        assert!(r.systemd_args.is_empty());

        let names = args(&["curl"]);
        let r = resolve_with(&configs, "curl", &[], select(&names, false)).unwrap();
        assert!(has_arg(&r.systemd_args, "CPUQuota=50%"));
    }

    #[test]
    fn extend() {
        let base = never_profile(vec![
            ("CPUQuota", str("50%")),
            ("ReadOnlyPaths", arr(&["/"])),
        ]);
        let mut child = profile(
            CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Glob(Pattern::new("cu*").unwrap(), MatchTarget::Command),
            vec![("MemoryMax", str("512M"))],
        );
        let exact_p = profile(
            CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
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
                CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
        s.iter().map(ToString::to_string).collect()
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
                CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
                vec![("BindPaths", arr(&["/always", "$arg_optional"]))],
            ),
        )]);
        let r = resolve(&configs, "app", &[]).unwrap();
        // $arg_optional not set → empty → filtered; only /always remains
        assert!(has_arg(&r.systemd_args, "BindPaths=/always"));
        let count = r
            .systemd_args
            .windows(2)
            .filter(|w| {
                assert_eq!(w.len(), 2);
                w[0] == "-p" && w[1].starts_with("BindPaths=")
            })
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
        result.unwrap_err();
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
                CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
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
    #[expect(clippy::many_single_char_names)]
    fn multi_extend_diamond() {
        // A extends [B, C]; B and C both extend D.
        // Diamond inheritance must not cause a circular-extend error.
        let d = never_profile(vec![("MemoryMax", str("64M"))]);
        let mut b = never_profile(vec![("CPUQuota", str("10%"))]);
        b.extend = vec!["d".into()];
        let mut c = never_profile(vec![("CPUQuota", str("20%"))]);
        c.extend = vec!["d".into()];
        let mut a = profile(
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
            vec![],
        );
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
        let mut child = profile(
            CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
            vec![],
        );
        child.extend = vec!["a".into()];

        let configs = make_configs(vec![("a", a), ("b", b), ("app", child)]);
        resolve(&configs, "app", &[]).unwrap_err();
    }

    #[test]
    fn full_command_target_match() {
        use crate::config::MatchTarget;
        use glob::Pattern;
        // Profile matches only when "commit" appears in the full command line.
        let p = profile(
            CommandPattern::Glob(
                Pattern::new("git commit*").unwrap(),
                MatchTarget::FullCommand,
            ),
            vec![("CPUQuota", str("10%"))],
        );
        let configs = make_configs(vec![("git-commit-sandbox", p)]);

        // Matches when "commit" is the first argument.
        let r = resolve(&configs, "git", &args(&["commit", "-m", "msg"])).unwrap();
        assert!(has_arg(&r.systemd_args, "CPUQuota=10%"));

        // Does not match when no arguments contain "commit".
        let r = resolve(&configs, "git", &args(&["status"])).unwrap();
        assert!(r.systemd_args.is_empty());

        // Does not match on command name alone (without matching args).
        let r = resolve(&configs, "git", &[]).unwrap();
        assert!(r.systemd_args.is_empty());
    }

    // ── multi-pattern match semantics ─────────────────────────────────────────

    fn matched(configs: &ValidatedConfigMap, command: &str, command_args: &[&str]) -> bool {
        !resolve(configs, command, &args(command_args))
            .unwrap()
            .systemd_args
            .is_empty()
    }

    #[test]
    fn command_names_in_array_are_alternatives() {
        let configs = configs_from_toml(
            r#"
            [ov]
            match = ["ov", "openviking", "openviking-server"]
            systemd.CPUQuota = "10%"
            "#,
        );
        assert!(matched(&configs, "ov", &["health"]));
        assert!(matched(&configs, "openviking", &[]));
        assert!(matched(&configs, "openviking-server", &[]));
        assert!(!matched(&configs, "other", &[]));
    }

    #[test]
    fn full_command_patterns_are_extra_conditions() {
        let configs = configs_from_toml(
            r#"
            [git-commit]
            match = ["git", { pattern = "\\bcommit\\b", type = "regex", target = "full_command" }]
            systemd.CPUQuota = "10%"
            "#,
        );
        assert!(matched(&configs, "git", &["commit", "-m", "x"]));
        assert!(!matched(&configs, "git", &["status"]));
        assert!(!matched(&configs, "hg", &["commit"]));
    }

    #[test]
    fn alternatives_combine_with_full_command_conditions() {
        let configs = configs_from_toml(
            r#"
            [vcs-commit]
            match = ["git", "hg", { pattern = "commit", type = "regex", target = "full_command" }]
            systemd.CPUQuota = "10%"
            "#,
        );
        assert!(matched(&configs, "hg", &["commit"]));
        assert!(matched(&configs, "git", &["commit"]));
        assert!(!matched(&configs, "hg", &["log"]));
        assert!(!matched(&configs, "svn", &["commit"]));
    }

    #[test]
    fn tier_comes_from_the_pattern_that_matched() {
        let configs = configs_from_toml(
            r#"
            [named]
            match = ["ov", { pattern = "o*", type = "glob" }]
            systemd.CPUQuota = "10%"

            [wide]
            match = { pattern = "*", type = "glob" }
            systemd.CPUQuota = "90%"
            "#,
        );
        // `ov` hits the exact entry, so `named` outranks the glob-only `wide`.
        let r = resolve(&configs, "ov", &[]).unwrap();
        assert!(has_arg(&r.systemd_args, "CPUQuota=10%"));
        assert!(!has_arg(&r.systemd_args, "CPUQuota=90%"));
        assert!(
            r.match_log
                .iter()
                .any(|l| l.contains("'named' matched exact"))
        );

        // `oo` only hits the glob entry, so `named` is a glob match too.
        let r = resolve(&configs, "oo", &[]).unwrap();
        assert!(
            r.match_log
                .iter()
                .any(|l| l.contains("'named' matched glob"))
        );
    }

    #[test]
    fn sentinel_adds_parent_names_as_alternatives() {
        let configs = configs_from_toml(
            r#"
            [base]
            match = ["base"]

            [child]
            extend = "base"
            match = ["...", "extra"]
            systemd.CPUQuota = "10%"
            "#,
        );
        assert!(matched(&configs, "base", &[]));
        assert!(matched(&configs, "extra", &[]));
        assert!(!matched(&configs, "other", &[]));
    }
    // ── explicit profile selection tests ──────────────────────────────────────

    fn select(profiles: &[String], no_match: bool) -> ResolveOptions<'_> {
        ResolveOptions { profiles, no_match }
    }

    #[test]
    fn explicit_profile_bypasses_match() {
        // A profile that never matches on its own is applied when named explicitly.
        let configs = make_configs(vec![(
            "netblock",
            never_profile(vec![("PrivateNetwork", Value::Boolean(true))]),
        )]);
        let names = args(&["netblock"]);
        let r = resolve_with(&configs, "curl", &[], select(&names, false)).unwrap();
        assert!(has_arg(&r.systemd_args, "PrivateNetwork=yes"));
    }

    #[test]
    fn explicit_profile_appended_to_matches() {
        // Matched profiles still apply; the explicit one wins on conflicting keys.
        let matched = profile(
            CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
            vec![("MemoryMax", str("1G")), ("CPUQuota", str("10%"))],
        );
        let extra = never_profile(vec![("MemoryMax", str("2G"))]);
        let configs = make_configs(vec![("curl", matched), ("extra", extra)]);

        let names = args(&["extra"]);
        let r = resolve_with(&configs, "curl", &[], select(&names, false)).unwrap();
        assert!(has_arg(&r.systemd_args, "CPUQuota=10%"));
        assert!(has_arg(&r.systemd_args, "MemoryMax=2G"));
        assert!(!has_arg(&r.systemd_args, "MemoryMax=1G"));
    }

    #[test]
    fn no_match_ignores_matching_profiles() {
        let matched = profile(
            CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
            vec![("CPUQuota", str("10%"))],
        );
        let extra = never_profile(vec![("MemoryMax", str("2G"))]);
        let configs = make_configs(vec![("curl", matched), ("extra", extra)]);

        let names = args(&["extra"]);
        let r = resolve_with(&configs, "curl", &[], select(&names, true)).unwrap();
        assert!(has_arg(&r.systemd_args, "MemoryMax=2G"));
        assert!(!has_arg(&r.systemd_args, "CPUQuota=10%"));
    }

    #[test]
    fn no_match_without_profiles_is_empty() {
        let configs = make_configs(vec![(
            "curl",
            profile(
                CommandPattern::Exact("curl".to_owned(), MatchTarget::Command),
                vec![("CPUQuota", str("10%"))],
            ),
        )]);
        let r = resolve_with(&configs, "curl", &[], select(&[], true)).unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn explicit_profile_not_found_errors() {
        let configs = make_configs(vec![("base", never_profile(vec![]))]);
        let names = args(&["bsae"]);
        resolve_with(&configs, "curl", &[], select(&names, false)).unwrap_err();
    }

    #[test]
    fn explicit_synthetic_name_not_selectable() {
        // Keys generated by cross-file self-extend must stay internal.
        let synthetic = "\u{0}app\u{0}0";
        let configs = make_configs(vec![(
            synthetic,
            never_profile(vec![("CPUQuota", str("10%"))]),
        )]);
        let names = args(&[synthetic]);
        resolve_with(&configs, "app", &[], select(&names, false)).unwrap_err();
    }

    #[test]
    fn explicit_profile_deduped_against_match() {
        // A profile that both matches and is named explicitly is applied once only.
        let configs = make_configs(vec![(
            "app",
            profile(
                CommandPattern::Exact("app".to_owned(), MatchTarget::Command),
                vec![("CPUQuota", str("10%"))],
            ),
        )]);
        let names = args(&["app", "app"]);
        let r = resolve_with(&configs, "app", &[], select(&names, false)).unwrap();

        assert!(has_arg(&r.systemd_args, "CPUQuota=10%"));
        let mentions = r
            .match_log
            .iter()
            .filter(|line| line.starts_with("profile 'app'"))
            .count();
        assert_eq!(mentions, 1);
        assert!(
            r.match_log
                .iter()
                .any(|l| l.contains("selected explicitly"))
        );
    }

    #[test]
    fn explicit_profiles_applied_in_cli_order() {
        let a = never_profile(vec![("CPUQuota", str("10%"))]);
        let b = never_profile(vec![("CPUQuota", str("20%"))]);
        let configs = make_configs(vec![("a", a), ("b", b)]);

        let names = args(&["a", "b"]);
        let r = resolve_with(&configs, "app", &[], select(&names, false)).unwrap();
        assert!(has_arg(&r.systemd_args, "CPUQuota=20%"));
    }

    #[test]
    fn log_settings_inherit_through_extend() {
        let configs = configs_from_toml(
            r#"
            [base]
            log.level = "debug"
            log.target = "file"
            log.path = "/tmp/scudo.log"

            [curl]
            match = "curl"
            extend = "base"
            log.level = "trace"
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert_eq!(resolved.log.level, Some(Level::Trace));
        // What the child said nothing about still comes from the parent.
        assert_eq!(resolved.log.targets, Some(vec![Target::File]));
        assert_eq!(resolved.log.path.as_deref(), Some("/tmp/scudo.log"));
    }

    /// A catch-all glob is how a global default is written, so an exact match
    /// has to be able to turn it down as well as up.
    #[test]
    fn an_exact_match_overrides_the_catch_all_in_both_directions() {
        let configs = configs_from_toml(
            r#"
            [default]
            match = { type = "glob", pattern = "*" }
            log.level = "debug"

            [curl]
            match = "curl"
            log.level = "error"
            "#,
        );
        assert_eq!(
            resolve(&configs, "curl", &[]).unwrap().log.level,
            Some(Level::Error)
        );
        assert_eq!(
            resolve(&configs, "wget", &[]).unwrap().log.level,
            Some(Level::Debug)
        );
    }

    /// `verbose` predates the log table; it is the same request in fewer words.
    #[test]
    fn verbose_asks_for_debug() {
        let configs = configs_from_toml("[curl]\nmatch = \"curl\"\nverbose = true\n");
        assert_eq!(
            resolve(&configs, "curl", &[]).unwrap().log.level,
            Some(Level::Debug)
        );
    }

    /// A level written out says more than the boolean can, so it is not
    /// overruled by it.
    #[test]
    fn an_explicit_level_beats_verbose() {
        let configs =
            configs_from_toml("[curl]\nmatch = \"curl\"\nverbose = true\nlog.level = \"error\"\n");
        assert_eq!(
            resolve(&configs, "curl", &[]).unwrap().log.level,
            Some(Level::Error)
        );
    }

    #[test]
    fn a_log_path_expands_environment_variables() {
        // SAFETY: single-threaded test setup, as elsewhere in this file.
        unsafe { std::env::set_var("SCUDO_TEST_LOG_DIR", "/var/tmp") }
        let configs = configs_from_toml(
            "[curl]\nmatch = \"curl\"\nlog.path = \"$SCUDO_TEST_LOG_DIR/s.log\"\n",
        );
        assert_eq!(
            resolve(&configs, "curl", &[]).unwrap().log.path.as_deref(),
            Some("/var/tmp/s.log")
        );
    }

    #[test]
    fn network_policy_is_resolved_from_the_profile() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1"]
            network.ports.allow = [53]
            "#,
            "curl",
            &[],
        );
        assert_eq!(policy.dest.allow.len(), 1);
        assert_eq!(policy.ports.allow.len(), 1);
        assert!(policy.requires_enforcer());
    }

    fn filesystem_policy(src: &str, command: &str) -> Option<FilesystemPolicy> {
        let configs = configs_from_toml(src);
        resolve(&configs, command, &[])
            .unwrap()
            .policies
            .into_iter()
            .find_map(|policy| match policy {
                Policy::Filesystem(fs) => Some(fs),
                Policy::Network(_) => None,
            })
    }

    #[test]
    fn filesystem_reporting_is_resolved_from_the_profile() {
        let policy = filesystem_policy(
            r#"
            [curl]
            match = ["curl"]
            filesystem.log = "denied"
            "#,
            "curl",
        )
        .expect("a filesystem policy");
        assert!(policy.reports_denials());
    }

    /// A profile that says nothing about it produces no policy at all, which is
    /// what leaves room for `--tui` to add one.
    #[test]
    fn a_profile_that_says_nothing_produces_no_filesystem_policy() {
        assert!(
            filesystem_policy(
                r#"
                [curl]
                match = ["curl"]
                systemd.PrivateTmp = true
                "#,
                "curl",
            )
            .is_none()
        );
    }

    /// It merges field by field like `log`, so a child that only turns it off
    /// does not have to restate anything.
    #[test]
    fn filesystem_settings_inherit_through_extend() {
        let src = r#"
            [base]
            filesystem.log = "denied"

            [curl]
            match = ["curl"]
            extend = ["base"]

            [wget]
            match = ["wget"]
            extend = ["base"]
            filesystem.log = "off"
        "#;
        assert!(
            filesystem_policy(src, "curl")
                .expect("inherited")
                .reports_denials()
        );
        // Written out, so it wins over what it extends — and it is still a
        // policy, because saying "off" is not the same as saying nothing.
        assert!(
            !filesystem_policy(src, "wget")
                .expect("declared off")
                .reports_denials()
        );
    }

    /// A `filesystem` table must not leak into the flattened systemd
    /// properties: it is scudo's setting, not a unit property.
    #[test]
    fn filesystem_is_not_a_systemd_property() {
        let configs = configs_from_toml(
            r#"
            [curl]
            match = ["curl"]
            filesystem.log = "denied"
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert!(
            !resolved
                .systemd_args
                .iter()
                .any(|a| a.starts_with("filesystem")),
            "{:?}",
            resolved.systemd_args
        );
    }

    /// A `network` table must not leak into the flattened systemd properties.
    #[test]
    fn network_is_not_a_systemd_property() {
        let configs = configs_from_toml(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1"]
            systemd.MemoryMax = "256M"
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert!(has_arg(&resolved.systemd_args, "MemoryMax=256M"));
        assert!(
            !resolved
                .systemd_args
                .iter()
                .any(|a| a.starts_with("network"))
        );
    }

    #[test]
    fn network_inherits_through_extend() {
        let policy = resolved_policy(
            r#"
            [base]
            network.dest.allow = ["1.1.1.1"]
            network.dest.deny = ["10.0.0.0/8"]
            network.on_unavailable = "no-network"

            [curl]
            match = "curl"
            extend = "base"
            network.dest.allow = ["...", "api.github.com"]
            "#,
            "curl",
            &[],
        );
        assert_eq!(
            policy.dest.allow,
            vec![
                Destination::Net {
                    addr: "1.1.1.1".parse().unwrap(),
                    prefix_len: 32u8,
                },
                Destination::Host("api.github.com".to_owned()),
            ]
        );
        // The half the child never mentioned survives the merge.
        assert_eq!(
            policy.dest.deny,
            vec![Destination::Net {
                addr: "10.0.0.0".parse().unwrap(),
                prefix_len: 8u8,
            }]
        );
        // Untouched fields are inherited as they are.
        assert_eq!(policy.on_unavailable, OnUnavailable::NoNetwork);
    }

    /// A child that only speaks about `ports` must not wipe the `dest` table it
    /// inherited: the network table nests, so the merge has to descend into it
    /// instead of replacing a sub-table wholesale.
    #[test]
    fn network_subtables_merge_instead_of_replacing() {
        let policy = resolved_policy(
            r#"
            [base]
            network.dest.allow = ["1.1.1.1"]
            network.ports.deny = [22]

            [curl]
            match = "curl"
            extend = "base"
            network.ports.allow = [443]
            "#,
            "curl",
            &[],
        );
        assert_eq!(
            policy.dest.allow,
            vec![Destination::Net {
                addr: "1.1.1.1".parse().unwrap(),
                prefix_len: 32u8,
            }]
        );
        assert_eq!(policy.ports.allow.len(), 1);
        assert_eq!(policy.ports.deny.len(), 1);
    }

    /// Without the sentinel, a child's list replaces the inherited one — the
    /// same rule as for every other array-valued property.
    #[test]
    fn network_list_without_sentinel_replaces() {
        let policy = resolved_policy(
            r#"
            [base]
            network.dest.allow = ["1.1.1.1"]

            [curl]
            match = "curl"
            extend = "base"
            network.dest.allow = ["api.github.com"]
            "#,
            "curl",
            &[],
        );
        assert_eq!(
            policy.dest.allow,
            vec![Destination::Host("api.github.com".to_owned())]
        );
    }

    #[test]
    fn network_scalars_are_overridden_by_the_child() {
        let policy = resolved_policy(
            r#"
            [base]
            network.default = "deny"
            network.on_unavailable = "fail"
            network.dest.allow = ["1.1.1.1"]

            [curl]
            match = "curl"
            extend = "base"
            network.on_unavailable = "no-network"
            "#,
            "curl",
            &[],
        );
        assert_eq!(policy.on_unavailable, OnUnavailable::NoNetwork);
        assert_eq!(policy.default, Action::Deny);
    }

    /// A profile can ask to be told what it blocks, without the rest of the
    /// verbose output coming with it.
    #[test]
    fn a_profile_can_turn_denial_reporting_on() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.log = "denied"
            network.dest.allow = ["1.1.1.1"]
            "#,
            "curl",
            &[],
        );
        assert_eq!(policy.log, LogLevel::Denied);
        assert!(policy.reports_denials());
    }

    /// Off unless asked: reporting costs a ring buffer and a process to read
    /// it, and most commands run with nobody watching.
    #[test]
    fn reporting_is_off_by_default() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1"]
            "#,
            "curl",
            &[],
        );
        assert_eq!(policy.log, LogLevel::Off);
        assert!(!policy.reports_denials());
    }

    /// A policy realised by taking the network away is still watchable: an
    /// observer is attached beside the empty netns, so asking to be told what
    /// was unreachable is answered rather than silently dropped.
    #[test]
    fn a_networkless_policy_is_still_reported() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.log = "denied"
            "#,
            "curl",
            &[],
        );
        assert!(policy.is_deny_all());
        assert!(policy.reports_denials());
        assert!(policy.observer().is_some());
    }

    /// Nobody asked, so nothing is attached: the observer costs a ring buffer
    /// and a process, and the deny-all path is the one that needs neither.
    #[test]
    fn a_networkless_policy_nobody_watches_attaches_nothing() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network = {}
            "#,
            "curl",
            &[],
        );
        assert!(policy.is_deny_all());
        assert!(!policy.reports_denials());
        assert!(policy.observer().is_none());
    }

    /// Resolving a profile only collects the policy; the properties it needs
    /// are the enforcer's business, so none are emitted here.
    #[test]
    fn resolving_a_policy_emits_no_properties_of_its_own() {
        let configs = configs_from_toml(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1", "example.com"]
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert!(resolved.systemd_args.is_empty());
        assert_eq!(resolved.policies.len(), 1);
    }

    /// Denying everything needs no enforcer, so it needs no extra properties
    /// either: `policy::apply` turns it into `PrivateNetwork=yes`.
    #[test]
    fn deny_all_policy_adds_no_properties() {
        let configs = configs_from_toml(
            r#"
            [curl]
            match = "curl"
            network = {}
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert!(resolved.systemd_args.is_empty());
        assert_eq!(resolved.policies.len(), 1);
    }

    /// A policy that restricts nothing is dropped rather than carried around.
    #[test]
    fn unrestricted_policy_is_dropped() {
        let configs = configs_from_toml(
            r#"
            [curl]
            match = "curl"
            network.default = "allow"
            network.inbound = "allow"
            "#,
        );
        let resolved = resolve(&configs, "curl", &[]).unwrap();
        assert!(resolved.policies.is_empty());
    }

    #[test]
    fn network_rules_expand_argument_variables() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["$arg_1"]
            "#,
            "curl",
            &["api.github.com"],
        );
        assert_eq!(
            policy.dest.allow,
            vec![Destination::Host("api.github.com".to_owned())]
        );
    }

    /// A multi-valued `$arg_*` replicates the list element it appears in, the
    /// same way it does for array-valued systemd properties.
    #[test]
    fn multi_valued_argument_replicates_the_rule() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            arg_aliases.host = { flags = ["--host"], nargs = "+" }
            network.dest.allow = ["$arg_host"]
            "#,
            "curl",
            &["--host", "a.example", "b.example"],
        );
        assert_eq!(
            policy.dest.allow,
            vec![
                Destination::Host("a.example".to_owned()),
                Destination::Host("b.example".to_owned()),
            ]
        );
    }

    /// A multi-valued `$arg_*` replicates inside the port list too, and the
    /// two lists expand independently of one another.
    #[test]
    fn multi_valued_argument_fills_the_port_list() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            arg_aliases.port = { flags = ["--port"], nargs = "+" }
            network.dest.allow = ["api.github.com"]
            network.ports.allow = ["$arg_port"]
            "#,
            "curl",
            &["--port", "80", "443"],
        );
        assert_eq!(
            policy.dest.allow,
            vec![Destination::Host("api.github.com".to_owned())]
        );
        assert_eq!(
            policy.ports.allow,
            vec![
                PortRule {
                    ports: PortRange { start: 80, end: 80 },
                    proto: Protocol::Any,
                },
                PortRule {
                    ports: PortRange {
                        start: 443,
                        end: 443
                    },
                    proto: Protocol::Any,
                },
            ]
        );
    }

    /// An unset `$arg_*` drops the rule instead of producing a bogus one.
    #[test]
    fn missing_argument_drops_the_rule() {
        let policy = resolved_policy(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1", "$arg_2"]
            "#,
            "curl",
            &[],
        );
        assert_eq!(policy.dest.allow.len(), 1);
    }

    #[test]
    fn invalid_network_policy_is_rejected_at_load() {
        let raw: crate::config::ConfigMap = toml::from_str(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["10.0.0.0/33"]
            "#,
        )
        .unwrap();
        let err = ValidatedConfigMap::try_from(raw).unwrap_err();
        assert!(format!("{err:#}").contains("curl"));
    }
}

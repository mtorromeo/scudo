use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use toml::Value;
use tracing::warn;

use crate::{
    config::{ArgDecls, Fallback, Profile, ValidatedConfigMap, VarDecls, command_line},
    logging::{Level, LogConfig},
    policy::{
        Access, DbusConfig, FilesystemConfig, FilesystemOverrides, FilesystemPolicy, NetworkConfig,
        NetworkOverrides, NetworkPolicy, Policy, UnitMounts, mount_properties,
    },
};

#[derive(Debug)]
pub struct ResolvedProfile {
    pub systemd_args: Vec<String>,
    pub exec: Option<String>,
    /// Level and destination for scudo's own output, still without the command
    /// line's say: the caller layers that on top.
    pub log: LogConfig,
    pub confirm: bool,
    /// The variables, by name or glob, not copied from scudo's environment
    /// into the unit unless `allow_env` matches them too.
    pub deny_env: Vec<String>,
    pub allow_env: Vec<String>,
    pub match_log: Vec<String>,
    /// Policies to hand to `scudo-bpfd` before the command starts.
    pub policies: Vec<Policy>,
    /// What the command gets of the session bus. Realised only once it is
    /// known the command runs sandboxed at all.
    pub dbus: DbusConfig,
    /// The profiles whose `match` picked this command, as opposed to those
    /// selected with `--profile` or reached through `extend`.
    pub matched: Vec<String>,
    /// Profiles whose commands a broker runs in a sandbox of their own when
    /// they are started from inside this one; see [`crate::broker`].
    pub delegate: Vec<String>,
    /// Every path the command may write, expanded and absolute.
    pub writable: Vec<PathBuf>,
    /// The paths the profiles grant access to that were worked out from the
    /// request rather than written down: from `$PWD`, an `$arg_*`, a lookup
    /// variable or a relative path. Whoever asked controls them, which is what
    /// a delegated run has to check before it hands them over.
    pub derived: Vec<PathBuf>,
}

/// Maps arg variable names to their accumulated values (always a `Vec`).
/// Positionals are stored as `"1"`, `"2"`, `"rest"` — without the `arg_` prefix.
/// Declared flags are stored under their declared name, also without the prefix.
type ArgVars = HashMap<String, Vec<String>>;

/// What `$NAME` references can expand to beyond the environment.
struct Vars {
    args: ArgVars,
    /// Lookup variables, the global ones overridden by the profiles'.
    lookups: VarDecls,
}

/// Options controlling which profiles [`resolve_with`] applies.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResolveOptions<'a> {
    /// Profiles selected explicitly on the command line. They are applied after any
    /// matched profiles, so they take precedence; order is significant (later wins).
    pub profiles: &'a [String],
    /// Skip pattern matching entirely; only `profiles` are applied.
    pub no_match: bool,
    /// Network rules from the command line, applied after every profile.
    pub network: Option<&'a NetworkOverrides>,
    /// File accesses from the command line, which replace the profiles' for
    /// the paths they name.
    pub filesystem: Option<&'a FilesystemOverrides>,
    /// Lookup variables from the `[scudo]` table; a profile's own win.
    pub vars: Option<&'a VarDecls>,
}

/// Merge every profile that matches `command`, in definition order, and build
/// the systemd-run argument list.
pub fn resolve(
    configs: &ValidatedConfigMap,
    command: &str,
    command_args: &[String],
) -> Result<ResolvedProfile> {
    resolve_with(configs, command, command_args, ResolveOptions::default())
}

/// Like [`resolve`], but honouring explicit profile selection from the command line.
///
/// Explicitly selected profiles are applied after the matched ones, in the order
/// given, so they win on scalar values. A profile that both matches and is
/// selected explicitly is applied only once, in its explicit position.
pub fn resolve_with(
    configs: &ValidatedConfigMap,
    command: &str,
    command_args: &[String],
    opts: ResolveOptions<'_>,
) -> Result<ResolvedProfile> {
    // Resolved first so an unknown name fails before anything else happens.
    let selected = select_profiles(configs, opts.profiles)?;

    // A command run by path matches by its name, the way it was installed.
    let name = Path::new(command)
        .file_name()
        .map_or(command.into(), |n| n.to_string_lossy());

    let mut requested: Vec<(&str, String)> = Vec::new();
    let mut matched: Vec<String> = Vec::new();
    if !opts.no_match {
        let line = command_line(&name, command_args);
        for (profile_name, profile) in &configs.0 {
            if selected.contains(&profile_name.as_str()) {
                continue;
            }
            if let Some(pattern) = profile.patterns.iter().find(|p| p.matches(&name, &line)) {
                matched.push(profile_name.clone());
                requested.push((
                    profile_name,
                    format!("profile '{profile_name}' matched '{}'", pattern.as_str()),
                ));
            }
        }
    }
    requested.extend(
        selected
            .iter()
            .map(|n| (*n, format!("profile '{n}' selected explicitly"))),
    );

    let mut match_log: Vec<String> = Vec::new();
    let mut order: Vec<&str> = Vec::new();
    for (profile_name, reason) in requested {
        match_log.push(reason);
        // Already applied as somebody else's base, but a profile asked for in
        // its own right goes where it was asked for.
        order.retain(|n| *n != profile_name);
        linearize(
            configs,
            profile_name,
            &mut vec![profile_name],
            &mut order,
            &mut match_log,
        )?;
    }

    let mut merged = Profile::default();
    for profile_name in order {
        if let Some(profile) = configs.0.get(profile_name) {
            merged.merge(profile);
        }
    }

    let overrides = opts.network.filter(|overrides| !overrides.is_empty());
    if let Some(overrides) = overrides {
        match_log.push(format!(
            "network rules from the command line: {}",
            overrides.describe()
        ));
    }
    let files = opts.filesystem.filter(|files| !files.is_empty());
    if let Some(files) = files {
        match_log.push(format!(
            "filesystem rules from the command line: {}",
            files.describe()
        ));
    }

    let mut lookups = opts.vars.cloned().unwrap_or_default();
    lookups.extend(merged.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    let vars = Vars {
        args: parse_command_args(command_args, &merged.args),
        lookups,
    };
    let delegate = configs.delegates(&merged.delegate);
    let mut resolved = build_args(merged, match_log, &vars, overrides, files)?;
    resolved.matched = matched;
    resolved.delegate = delegate;
    Ok(resolved)
}

/// Look up explicitly requested profile names, preserving order and dropping duplicates.
///
/// An unknown name is an error: silently ignoring it would run the command with less
/// sandboxing than the user asked for.
fn select_profiles<'a>(configs: &'a ValidatedConfigMap, names: &[String]) -> Result<Vec<&'a str>> {
    let mut selected: Vec<&str> = Vec::new();
    for name in names {
        let (key, _) = configs
            .0
            .get_key_value(name.as_str())
            .with_context(|| format!("profile '{name}' not found"))?;
        if !selected.contains(&key.as_str()) {
            selected.push(key);
        }
    }
    Ok(selected)
}

/// Append `name` to `out`, after every profile it extends.
///
/// Parents are walked left to right, and a profile already in `out` is not
/// added again: a base shared by two profiles is applied once. `path` is the
/// branch being walked, for cycle detection.
fn linearize<'a>(
    configs: &'a ValidatedConfigMap,
    name: &str,
    path: &mut Vec<&'a str>,
    out: &mut Vec<&'a str>,
    log: &mut Vec<String>,
) -> Result<()> {
    if out.contains(&name) {
        return Ok(());
    }
    let (key, profile) = configs
        .0
        .get_key_value(name)
        .with_context(|| format!("extended profile '{name}' not found"))?;

    for parent in &profile.extend {
        if path.contains(&parent.as_str()) {
            bail!("circular profile extension: {parent}");
        }
        let indent = " ".repeat(path.len().saturating_mul(3).saturating_sub(1));
        log.push(format!("{indent}└─ extends '{parent}'"));

        path.push(parent);
        let walked = linearize(configs, parent, path, out, log);
        path.pop();
        walked?;
    }

    out.push(key);
    Ok(())
}

/// Parse `command_args` into a map of arg variable name → accumulated values.
///
/// - Declared flags take a value, as `--flag value` or `--flag=value`; every
///   occurrence adds to the same variable. A greedy one also takes every
///   argument after it up to the next one starting with `-`.
/// - Undeclared flags never take a value.
/// - `--` terminates option parsing; everything after is positional.
/// - Remaining args become `arg_1`, `arg_2`, … and `arg_rest` (space-joined).
fn parse_command_args(args: &[String], decls: &ArgDecls) -> ArgVars {
    let mut flags: HashMap<&str, (&str, bool)> = HashMap::new();
    for (var_name, decl) in decls {
        for flag in decl.flags() {
            flags.insert(flag.as_str(), (var_name.as_str(), decl.is_greedy()));
        }
    }

    let mut vars: ArgVars = HashMap::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut iter = args.iter().peekable();
    let is_value = |a: &&String| !a.starts_with('-');

    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') || arg == "-" {
            positionals.push(arg.clone());
            continue;
        }

        if arg == "--" {
            positionals.extend(iter.by_ref().cloned());
            break;
        }

        if let Some((flag, val)) = arg.split_once('=') {
            if let Some((var_name, _)) = flags.get(flag) {
                vars.entry((*var_name).to_owned())
                    .or_default()
                    .push(val.to_owned());
            }
            continue;
        }

        if let Some((var_name, greedy)) = flags.get(arg.as_str()).copied() {
            let values = vars.entry(var_name.to_owned()).or_default();
            if greedy {
                while let Some(val) = iter.next_if(is_value) {
                    values.push(val.clone());
                }
            } else if let Some(val) = iter.next() {
                values.push(val.clone());
            } else {
                // no value follows the flag — nothing to record
            }
        }
    }

    for (n, val) in positionals.iter().enumerate() {
        vars.insert(n.saturating_add(1).to_string(), vec![val.clone()]);
    }
    if !positionals.is_empty() {
        vars.insert("rest".to_owned(), vec![positionals.join(" ")]);
    }

    vars
}

/// The closest directory, `start` included, that holds any of `names` — a file
/// or a directory alike.
#[must_use]
pub fn find_up(start: &Path, names: &[String]) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| names.iter().any(|name| dir.join(name).exists()))
        .map(Path::to_path_buf)
}

/// Make a path absolute relative to the process's current directory.
/// Uses `std::path::absolute` which normalises `.` components lexically
/// without requiring the path to exist.
fn make_absolute(path: &str) -> String {
    std::path::absolute(path).map_or_else(|_| path.to_owned(), |p| p.to_string_lossy().into_owned())
}

/// Whether a variable appended to `partial` would open a path: nothing but
/// systemd's prefix characters follows the last `:` (`src:dst[:opts]`) or
/// whitespace (lists, `path weight`).
fn starts_path(partial: &str) -> bool {
    partial
        .rsplit(|c: char| c == ':' || c.is_whitespace())
        .next()
        .is_none_or(|tail| tail.chars().all(|c| matches!(c, '-' | '+' | '!' | '~')))
}

/// Returns `true` for systemd unit properties whose values are filesystem paths.
/// A variable expansion that opens a path within these properties is made absolute.
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
    profile: Profile,
    match_log: Vec<String>,
    vars: &Vars,
    overrides: Option<&NetworkOverrides>,
    files: Option<&FilesystemOverrides>,
) -> Result<ResolvedProfile> {
    let mut args = Vec::new();

    // Before `writable` is worked out: what the command line hides is no
    // longer the profiles' to hand to a broker.
    let mut entries = filesystem_entries(&profile.filesystem, vars)?;
    if let Some(files) = files {
        entries = files.apply(entries);
    }
    let writable = entries
        .iter()
        .filter(|(access, _)| *access == Access::Write)
        .map(|(_, path)| path.clone())
        .collect();
    let derived = derived_paths(&profile, vars)?;
    let mut unit = UnitMounts::default();
    for (key, val) in &profile.systemd {
        for value in value_to_strings(val, vars, is_path_property(key))? {
            unit.add(key, &value);
        }
    }
    let mounts = mount_properties(entries, &unit);
    for path in &mounts.unreachable {
        warn!(
            "{} is granted inside a directory the sandbox makes inaccessible, where systemd \
             cannot mount it: the grant has no effect",
            path.display()
        );
    }
    for (key, val) in mounts.properties {
        args.push("-p".into());
        args.push(format_property(key, &val));
    }

    for (key, val) in &profile.systemd {
        let path_prop = is_path_property(key);
        for str_val in value_to_strings(val, vars, path_prop)? {
            args.push("-p".into());
            args.push(format_property(key, &str_val));
        }
    }

    // The properties a policy needs are added by `policy::apply`, once it knows
    // the policy is actually being enforced: emitting them for a policy that
    // ends up degraded would restrict the command for no benefit.
    let policies = build_policies(profile.network, &profile.filesystem, vars, overrides)?;

    let mut log = profile.log;
    // `verbose` predates the log table and asks for the same thing in fewer
    // words. A level written out says more than the boolean can, so it wins.
    if profile.verbose == Some(true) && log.level.is_none() {
        log.level = Some(Level::Debug);
    }
    if let Some(path) = log.path {
        // A lookup variable that was not found leaves no log file.
        log.path = expand_vars(&path, vars, false)?.pop();
    }

    Ok(ResolvedProfile {
        systemd_args: args,
        exec: profile.exec,
        log,
        confirm: profile.confirm.unwrap_or(false),
        deny_env: profile.deny_env,
        allow_env: profile.allow_env,
        match_log,
        policies,
        dbus: profile.dbus,
        matched: Vec::new(),
        delegate: Vec::new(),
        writable,
        derived,
    })
}

/// The paths the profile grants access to that the request decided; see
/// [`ResolvedProfile::derived`].
///
/// Only grants count: `hide` and `deny` take access away, whatever path they
/// end up naming. A `src:dst` pair is checked on both sides, and a leading `-`
/// or `+`, which systemd reads as a flag, is not part of the path.
fn derived_paths(profile: &Profile, vars: &Vars) -> Result<Vec<PathBuf>> {
    let mut templates: Vec<(&str, bool)> = profile
        .filesystem
        .write
        .iter()
        .chain(&profile.filesystem.read)
        .map(|t| (t.as_str(), true))
        .collect();
    let mut systemd_values = Vec::new();
    for (key, val) in &profile.systemd {
        if is_path_property(key) {
            collect_strings(val, &mut systemd_values);
        }
    }
    templates.extend(systemd_values.iter().map(|t| (t.as_str(), true)));

    let mut paths = Vec::new();
    for (template, is_path) in templates {
        if !request_derived(template, vars)? {
            continue;
        }
        for value in expand_vars(template, vars, is_path)? {
            for side in value.split(':') {
                let side = side.trim_start_matches(['-', '+']);
                if !side.is_empty() {
                    paths.push(PathBuf::from(make_absolute(side)));
                }
            }
        }
    }
    Ok(paths)
}

fn collect_strings(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Integer(_)
        | Value::Float(_)
        | Value::Boolean(_)
        | Value::Datetime(_)
        | Value::Table(_) => {}
    }
}

/// Whether what `template` expands to depends on the request: the directory it
/// was made from, or the command's arguments.
///
/// Decided from the template, not from its value, and conservatively: a
/// default counts even when it ends up unused. `$PWD` is listed by name because
/// it is the request's directory, not the environment's, wherever the template
/// is expanded.
fn request_derived(template: &str, vars: &Vars) -> Result<bool> {
    let pieces = parse_template(template)?;
    if let Some(Piece::Literal(first)) = pieces.first() {
        let first = first.trim_start_matches(['-', '+']);
        if !first.starts_with('/') {
            return Ok(true);
        }
    }
    for piece in pieces {
        if let Piece::Var { name, default } = piece {
            if name.starts_with("arg_") || name == "PWD" || vars.lookups.contains_key(name) {
                return Ok(true);
            }
            if let Some(default) = default
                && request_derived(default, vars)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Expand the paths of the `filesystem` table, made absolute, each with the
/// access it was listed under. An entry that expands to nothing — an absent
/// `$arg_*` — is dropped.
fn filesystem_entries(fs: &FilesystemConfig, vars: &Vars) -> Result<Vec<(Access, PathBuf)>> {
    let lists = [
        (Access::Write, &fs.write),
        (Access::Read, &fs.read),
        (Access::Hide, &fs.hide),
        (Access::Deny, &fs.deny),
    ];
    let mut entries = Vec::new();
    for (access, list) in lists {
        for entry in list {
            for path in expand_vars(entry, vars, false)? {
                if !path.is_empty() {
                    entries.push((access, PathBuf::from(make_absolute(&path))));
                }
            }
        }
    }
    Ok(entries)
}

/// Turn the merged sub-tables into normalised policies.
///
/// A profile that asked for neither produces none, and the command is then
/// never registered with the daemon at all.
fn build_policies(
    network: Option<toml::Table>,
    filesystem: &FilesystemConfig,
    vars: &Vars,
    overrides: Option<&NetworkOverrides>,
) -> Result<Vec<Policy>> {
    let mut policies = Vec::new();

    let mut network_policy = None;
    if let Some(network) = network {
        let mut table = toml::Table::new();
        for (key, val) in network {
            if let Some(expanded) = expand_network_value(val, vars, false)? {
                table.insert(key, expanded);
            }
        }

        let config: NetworkConfig = toml::Value::Table(table)
            .try_into()
            .context("invalid network policy")?;
        network_policy = Some(NetworkPolicy::try_from(config).context("invalid network policy")?);
    }
    // The command line has the last word, and only what is left once it has
    // spoken decides whether there is anything to enforce.
    if let Some(overrides) = overrides {
        network_policy = overrides.apply(network_policy);
    }
    if let Some(policy) = network_policy
        && !policy.is_unrestricted()
    {
        policies.push(Policy::Network(policy));
    }

    // A table that said nothing about reporting is not one that says off:
    // leaving it out is what lets `--tui` fill the gap with one of its own.
    if let Some(log) = filesystem.log {
        policies.push(Policy::Filesystem(FilesystemPolicy { log }));
    }
    Ok(policies)
}

/// Expand `$VAR` and `$arg_*` references inside a network policy value.
///
/// Mirrors `value_to_strings`: a multi-valued `$arg_*` replicates the list
/// element it appears in, and an element expanding to nothing is dropped.
/// Anywhere but a list there is nothing to replicate, so a multi-valued
/// expansion is an error rather than a silent truncation.
fn expand_network_value(val: Value, vars: &Vars, in_list: bool) -> Result<Option<Value>> {
    match val {
        Value::String(s) => {
            let mut expanded = expand_vars(&s, vars, false)?;
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
                match expand_network_value(item, vars, true)? {
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
                if let Some(value) = expand_network_value(item, vars, false)? {
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
fn value_to_strings(val: &Value, vars: &Vars, is_path: bool) -> Result<Vec<String>> {
    match val {
        Value::String(s) => expand_vars(s, vars, is_path),
        Value::Boolean(b) => Ok(vec![if *b { "yes" } else { "no" }.to_owned()]),
        Value::Integer(n) => Ok(vec![n.to_string()]),
        Value::Float(f) => Ok(vec![f.to_string()]),
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                for s in value_to_strings(item, vars, is_path)? {
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

/// Expand `$VAR`, `${VAR}`, `${VAR:-DEFAULT}` and `$arg_*` references in `s`.
///
/// - `$arg_name` / `${arg_name}` look up `name` in `arg_vars` (silently empty if absent).
///   If the variable holds N > 1 values, the template is replicated N times (one per value).
///   Having more than one multi-value `$arg_*` reference in the same template is an error.
/// - A lookup variable is the closest directory holding what it looks for; see
///   [`find_up`]. When there is none its fallback decides, and `skip` makes the
///   whole of `s` expand to nothing.
/// - All other `$VAR` references are resolved from the environment; missing vars are an error.
/// - `${VAR:-DEFAULT}` expands `DEFAULT` instead when `VAR` is unset or empty: an
///   `$arg_*` with no value, a lookup variable that finds nothing (its own fallback
///   is not consulted), a missing environment variable. `DEFAULT` is itself a
///   template, expanded only when it is used, so defaults can chain.
/// - When `is_path` is `true`, a variable value that opens a path (see [`starts_path`])
///   is made absolute using the process's current directory; one inside a path component,
///   as in `/tmp/app-$UID`, is inserted as it is. Literal text in the template is left
///   untouched, except in a default taking a variable's place.
///
/// Returns a `Vec<String>` (usually one element; N elements when an array arg causes
/// explosion; none when a lookup variable is skipped).
fn expand_vars(s: &str, vars: &Vars, is_path: bool) -> Result<Vec<String>> {
    // We maintain a Vec of partially-built strings.
    // Most of the time this has exactly one element; it grows when an array arg is expanded.
    let mut results: Vec<String> = vec![String::new()];
    let mut array_var_seen = false;

    for piece in parse_template(s)? {
        let (name, default) = match piece {
            Piece::Literal(text) => {
                for r in &mut results {
                    r.push_str(text);
                }
                continue;
            }
            Piece::Var { name, default } => (name, default),
        };

        let values = match resolve_var(name, vars, default.is_some())? {
            Resolved::Values(values) => values,
            Resolved::Skip => return Ok(Vec::new()),
            Resolved::Unset => match default {
                Some(default) => {
                    let values = expand_vars(default, vars, is_path)?;
                    if values.is_empty() {
                        return Ok(Vec::new());
                    }
                    values
                }
                None => vec![String::new()],
            },
        };
        // Decided per partial result: an earlier array variable can leave them
        // ending differently.
        let push = |existing: &mut String, val: &str| {
            if is_path && !val.is_empty() && starts_path(existing) {
                existing.push_str(&make_absolute(val));
            } else {
                existing.push_str(val);
            }
        };

        if values.len() > 1 {
            if array_var_seen {
                bail!("string template '{s}' contains more than one array argument variable");
            }
            array_var_seen = true;
            // Explode: for each existing partial result × each value
            let mut new_results = Vec::with_capacity(results.len().saturating_mul(values.len()));
            for existing in &results {
                for val in &values {
                    let mut new = existing.clone();
                    push(&mut new, val);
                    new_results.push(new);
                }
            }
            results = new_results;
        } else {
            for r in &mut results {
                push(r, values.first().map_or("", String::as_str));
            }
        }
    }

    Ok(results)
}

/// What a variable reference resolves to before any default is applied.
enum Resolved {
    Values(Vec<String>),
    /// Nothing to expand: the reference's default applies, or else it is empty.
    Unset,
    /// A lookup variable with `fallback = "skip"` found nothing.
    Skip,
}

/// Resolve `name` as an argument, lookup or environment variable. With
/// `has_default`, anything missing is [`Resolved::Unset`] instead of being
/// settled by the variable's own fallback or turned into an error.
fn resolve_var(name: &str, vars: &Vars, has_default: bool) -> Result<Resolved> {
    if let Some(arg_name) = name.strip_prefix("arg_") {
        return Ok(match vars.args.get(arg_name) {
            Some(values) if values.iter().any(|v| !v.is_empty()) => {
                Resolved::Values(values.clone())
            }
            _ => Resolved::Unset,
        });
    }

    if let Some(decl) = vars.lookups.get(name) {
        let cwd = std::env::current_dir().context("finding the current directory")?;
        let dir = match (find_up(&cwd, &decl.lookup), decl.fallback) {
            (Some(dir), _) => dir,
            (None, _) if has_default => return Ok(Resolved::Unset),
            (None, Fallback::Cwd) => cwd,
            (None, Fallback::Skip) => return Ok(Resolved::Skip),
            (None, Fallback::Error) => bail!(
                "variable '${name}': none of {} found in {} or above",
                decl.lookup.join(", "),
                cwd.display()
            ),
        };
        return Ok(Resolved::Values(vec![dir.to_string_lossy().into_owned()]));
    }

    match std::env::var(name) {
        Ok(val) if !val.is_empty() || !has_default => Ok(Resolved::Values(vec![val])),
        Err(e) if !has_default => {
            Err(e).with_context(|| format!("undefined environment variable '${name}'"))
        }
        _ => Ok(Resolved::Unset),
    }
}

/// A piece of a string template.
#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    Literal(&'a str),
    /// `$NAME`, `${NAME}` or `${NAME:-DEFAULT}`.
    Var {
        name: &'a str,
        default: Option<&'a str>,
    },
}

/// Split `s` into literal text and variable references. A `$` that starts no
/// reference is literal; the default of `${NAME:-…}` may hold further braces,
/// as long as they are balanced.
fn parse_template(s: &str) -> Result<Vec<Piece<'_>>> {
    let mut pieces = Vec::new();
    let mut rest = s;

    while let Some((literal, after)) = rest.split_once('$') {
        if !literal.is_empty() {
            pieces.push(Piece::Literal(literal));
        }
        if let Some(inner) = after.strip_prefix('{') {
            let (body, tail) =
                split_braced(inner).with_context(|| format!("unterminated '${{' in '{s}'"))?;
            let (name, default) = match body.split_once(":-") {
                Some((name, default)) => (name, Some(default)),
                None => (body, None),
            };
            if name.is_empty() {
                bail!("empty variable name in '{s}'");
            }
            pieces.push(Piece::Var { name, default });
            rest = tail;
        } else {
            let end = after
                .char_indices()
                .find(|&(i, c)| {
                    !(c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
                })
                .map_or(after.len(), |(i, _)| i);
            let (name, tail) = after.split_at(end);
            pieces.push(if name.is_empty() {
                // Not a reference: keep the `$` as text.
                Piece::Literal("$")
            } else {
                Piece::Var {
                    name,
                    default: None,
                }
            });
            rest = tail;
        }
    }
    if !rest.is_empty() {
        pieces.push(Piece::Literal(rest));
    }
    Ok(pieces)
}

/// Split `s` around the `}` closing a `${`, past any balanced braces before it.
fn split_braced(s: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth = depth.checked_add(1)?,
            '}' => {
                if let Some(d) = depth.checked_sub(1) {
                    depth = d;
                } else {
                    let (body, tail) = s.split_at(i);
                    return Some((body, tail.strip_prefix('}')?));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[expect(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{
        logging::Target,
        policy::network::{
            Action, Destination, LogLevel, OnUnavailable, PortRange, PortRule, Protocol,
        },
    };

    /// Expand `$VAR` and `${VAR}` using the current process environment alone.
    fn expand_env(s: &str) -> Result<String> {
        let vars = Vars {
            args: ArgVars::new(),
            lookups: VarDecls::new(),
        };
        let mut results = expand_vars(s, &vars, false)?;
        Ok(results.pop().unwrap_or_default())
    }

    /// Build a config map through the real load pipeline, so that these tests
    /// exercise validation as well as merging.
    fn configs_from_toml(src: &str) -> ValidatedConfigMap {
        let raw: crate::config::ConfigMap = toml::from_str(src).unwrap();
        raw.try_into().unwrap()
    }

    fn resolved_policy(src: &str, command: &str, args: &[&str]) -> NetworkPolicy {
        let configs = configs_from_toml(src);
        let resolved = resolve(&configs, command, &self::args(args)).unwrap();
        resolved
            .policies
            .into_iter()
            .find_map(|policy| match policy {
                Policy::Network(network) => Some(network),
                Policy::Filesystem(_) => None,
            })
            .expect("expected a network policy")
    }

    #[expect(clippy::missing_asserts_for_indexing)]
    fn has_arg(args: &[String], kv: &str) -> bool {
        args.windows(2).any(|w| w[0] == "-p" && w[1] == kv)
    }

    /// Every value emitted for one property, in the order they were emitted.
    #[expect(clippy::missing_asserts_for_indexing)]
    fn values(args: &[String], key: &str) -> Vec<String> {
        let prefix = format!("{key}=");
        args.windows(2)
            .filter(|w| w[0] == "-p" && w[1].starts_with(&prefix))
            .filter_map(|w| w[1].strip_prefix(&prefix).map(ToOwned::to_owned))
            .collect()
    }

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(ToString::to_string).collect()
    }

    fn systemd_args(src: &str, command: &str, command_args: &[&str]) -> Vec<String> {
        resolve(&configs_from_toml(src), command, &args(command_args))
            .unwrap()
            .systemd_args
    }

    fn select(profiles: &[String], no_match: bool) -> ResolveOptions<'_> {
        ResolveOptions {
            profiles,
            no_match,
            ..ResolveOptions::default()
        }
    }

    fn selected_args(src: &str, profiles: &[&str], command: &str) -> Vec<String> {
        let names = args(profiles);
        resolve_with(&configs_from_toml(src), command, &[], select(&names, false))
            .unwrap()
            .systemd_args
    }

    // ── matching ──────────────────────────────────────────────────────────────

    #[test]
    fn match_is_a_glob_on_the_command_name() {
        let src = r#"
            [curl]
            match = "curl"
            systemd.MemoryMax = "1G"

            [code]
            match = ["zed", "code*"]
            systemd.CPUQuota = "10%"
        "#;
        assert!(has_arg(&systemd_args(src, "curl", &[]), "MemoryMax=1G"));
        assert!(systemd_args(src, "wget", &[]).is_empty());
        assert!(has_arg(&systemd_args(src, "zed", &[]), "CPUQuota=10%"));
        assert!(has_arg(&systemd_args(src, "code-oss", &[]), "CPUQuota=10%"));
        // A command run by path matches by its name.
        assert!(has_arg(
            &systemd_args(src, "/usr/bin/curl", &[]),
            "MemoryMax=1G"
        ));
    }

    /// A pattern holding a space is compared with the command line, the name
    /// followed by the arguments; `/…/` is a regex, unanchored.
    #[test]
    fn match_reaches_the_command_line_and_takes_regexes() {
        let src = r#"
            [push]
            match = ["git push*", '/^npm( \S+)* (-g|--global)( |$)/']
            systemd.MemoryMax = "1G"

            [python]
            match = "/^python3?$/"
            systemd.CPUQuota = "10%"
        "#;
        assert!(has_arg(
            &systemd_args(src, "/usr/bin/git", &["push", "origin"]),
            "MemoryMax=1G"
        ));
        assert!(systemd_args(src, "git", &["status"]).is_empty());
        assert!(has_arg(
            &systemd_args(src, "npm", &["install", "-g", "x"]),
            "MemoryMax=1G"
        ));
        assert!(has_arg(
            &systemd_args(src, "npm", &["--global", "install", "x"]),
            "MemoryMax=1G"
        ));
        assert!(systemd_args(src, "npm", &["install", "x"]).is_empty());
        assert!(has_arg(
            &systemd_args(src, "python3", &["-c", "1"]),
            "CPUQuota=10%"
        ));
        assert!(systemd_args(src, "python3x", &[]).is_empty());
    }

    /// The example's `cargo-install` is applied to installs alone, on top of
    /// `cargo`, however cargo is reached.
    #[test]
    fn the_example_installs_with_cargo_install() {
        let configs = configs_from_toml(include_str!("../examples/config.toml"));
        let matched = |command: &str, command_args: &[&str]| {
            resolve(&configs, command, &args(command_args))
                .unwrap()
                .matched
        };
        for (command, command_args) in [
            ("cargo", &["install", "ripgrep"][..]),
            ("/usr/bin/cargo", &["binstall", "-y", "ripgrep"]),
            ("cargo", &["+nightly", "install", "--locked", "x"]),
            ("cargo", &["install-update", "-a"]),
        ] {
            assert_eq!(
                matched(command, command_args),
                ["cargo", "cargo-install"],
                "{command} {command_args:?}"
            );
        }
        assert_eq!(matched("cargo-binstall", &["ripgrep"]), ["cargo-install"]);
        assert_eq!(matched("cargo-install-update", &["-a"]), ["cargo-install"]);
        assert_eq!(matched("npm", &["publish"]), ["npm", "npm-auth"]);
        assert_eq!(matched("npm", &["login"]), ["npm", "npm-auth"]);
        assert_eq!(matched("npm", &["install", "publish"]), ["npm"]);
        for command_args in [&["build"][..], &["run", "--", "install"], &["installer"]] {
            assert_eq!(
                matched("cargo", command_args),
                ["cargo"],
                "{command_args:?}"
            );
        }
    }

    /// The section name is an identifier, not a pattern: without `match` the
    /// profile is invisible to the matcher, but still reachable by name.
    #[test]
    fn profile_without_match_is_only_reachable_by_name() {
        let src = "[curl]\nsystemd.CPUQuota = \"50%\"\n";
        assert!(systemd_args(src, "curl", &[]).is_empty());
        assert!(has_arg(
            &selected_args(src, &["curl"], "curl"),
            "CPUQuota=50%"
        ));
    }

    /// Several matches are applied in the order they were written, so the
    /// last one has the last word on a scalar.
    #[test]
    fn matches_apply_in_definition_order() {
        let src = r#"
            [all]
            match = "*"
            systemd.CPUQuota = "90%"
            systemd.BindPaths = ["/all"]

            [curl]
            match = "curl"
            systemd.CPUQuota = "10%"
            systemd.BindPaths = ["/curl"]
        "#;
        let r = systemd_args(src, "curl", &[]);
        assert_eq!(values(&r, "CPUQuota"), ["10%"]);
        assert_eq!(values(&r, "BindPaths"), ["/all", "/curl"]);
    }

    // ── merging ───────────────────────────────────────────────────────────────

    #[test]
    fn extend_applies_the_parent_first() {
        let src = r#"
            [base]
            systemd.CPUQuota = "50%"
            systemd.ReadOnlyPaths = ["/"]
            systemd.MemoryMax = "1G"

            [curl]
            match = "curl"
            extend = "base"
            systemd.ReadOnlyPaths = ["/etc"]
            systemd.MemoryMax = "2G"
        "#;
        let r = systemd_args(src, "curl", &[]);
        assert!(has_arg(&r, "CPUQuota=50%"));
        // Lists accumulate, scalars are the child's.
        assert_eq!(values(&r, "ReadOnlyPaths"), ["/", "/etc"]);
        assert_eq!(values(&r, "MemoryMax"), ["2G"]);
    }

    /// A diamond applies the shared base once, and both branches' additions
    /// survive.
    #[test]
    fn a_shared_base_is_applied_once() {
        let src = r#"
            [base]
            systemd.BindPaths = ["/base"]
            systemd.CPUQuota = "5%"

            [a]
            extend = "base"
            systemd.BindPaths = ["/a"]
            systemd.CPUQuota = "10%"

            [b]
            extend = "base"
            systemd.BindPaths = ["/b", "/base"]
            systemd.CPUQuota = "20%"

            [app]
            match = "app"
            extend = ["a", "b"]
            systemd.BindPaths = ["/app"]
        "#;
        let r = systemd_args(src, "app", &[]);
        assert_eq!(values(&r, "BindPaths"), ["/base", "/a", "/b", "/app"]);
        // The rightmost parent wins over the ones before it.
        assert_eq!(values(&r, "CPUQuota"), ["20%"]);
    }

    #[test]
    fn extend_circular_is_detected() {
        let configs = configs_from_toml(
            r#"
            [a]
            extend = "b"
            [b]
            extend = "a"
            [app]
            match = "app"
            extend = "a"
            "#,
        );
        let err = resolve(&configs, "app", &[]).unwrap_err();
        assert!(format!("{err:#}").contains("circular"));
    }

    #[test]
    fn extending_an_unknown_profile_errors() {
        let configs = configs_from_toml("[app]\nmatch = \"app\"\nextend = \"nope\"\n");
        resolve(&configs, "app", &[]).unwrap_err();
    }

    #[test]
    fn path_with_spaces_is_quoted() {
        let r = systemd_args(
            "[app]\nmatch = \"app\"\nsystemd.BindPaths = \"/home/user/My Documents\"\n",
            "app",
            &[],
        );
        assert!(has_arg(&r, "BindPaths=\"/home/user/My Documents\""));
    }

    // ── explicit selection ────────────────────────────────────────────────────

    #[test]
    fn explicit_profiles_apply_after_the_matches_in_cli_order() {
        let src = r#"
            [curl]
            match = "curl"
            systemd.MemoryMax = "1G"
            systemd.CPUQuota = "10%"

            [a]
            systemd.MemoryMax = "2G"

            [b]
            systemd.MemoryMax = "3G"
        "#;
        let r = selected_args(src, &["b", "a"], "curl");
        assert!(has_arg(&r, "CPUQuota=10%"));
        assert_eq!(values(&r, "MemoryMax"), ["2G"]);
    }

    #[test]
    fn no_match_applies_only_the_named_profiles() {
        let configs = configs_from_toml(
            "[curl]\nmatch = \"curl\"\nsystemd.CPUQuota = \"10%\"\n[extra]\nsystemd.MemoryMax = \"2G\"\n",
        );
        let names = args(&["extra"]);
        let r = resolve_with(&configs, "curl", &[], select(&names, true)).unwrap();
        assert!(has_arg(&r.systemd_args, "MemoryMax=2G"));
        assert!(!has_arg(&r.systemd_args, "CPUQuota=10%"));

        let r = resolve_with(&configs, "curl", &[], select(&[], true)).unwrap();
        assert!(r.systemd_args.is_empty());
    }

    #[test]
    fn explicit_profile_not_found_errors() {
        let configs = configs_from_toml("[base]\n");
        let names = args(&["bsae"]);
        resolve_with(&configs, "curl", &[], select(&names, false)).unwrap_err();
    }

    /// A profile that both matches and is named explicitly is applied once.
    #[test]
    fn explicit_profile_deduped_against_match() {
        let configs = configs_from_toml("[app]\nmatch = \"app\"\nsystemd.CPUQuota = \"10%\"\n");
        let names = args(&["app", "app"]);
        let r = resolve_with(&configs, "app", &[], select(&names, false)).unwrap();
        assert_eq!(values(&r.systemd_args, "CPUQuota"), ["10%"]);
        assert_eq!(r.match_log, ["profile 'app' selected explicitly"]);
    }

    /// A base already applied for a matched profile moves to where it was
    /// asked for by name, so it has the last word.
    #[test]
    fn an_explicit_base_moves_to_its_explicit_position() {
        let src = r#"
            [base]
            systemd.CPUQuota = "5%"

            [app]
            match = "app"
            extend = "base"
            systemd.CPUQuota = "10%"
        "#;
        assert_eq!(
            values(&selected_args(src, &["base"], "app"), "CPUQuota"),
            ["5%"]
        );
    }

    // ── scenario: combining profiles written separately ───────────────────────

    const COMBINED: &str = r#"
        [claude]
        match = "claude"
        filesystem.hide = ["/home/u"]
        filesystem.read = ["/", "/home/u/.gitconfig", "/srv/shared"]
        filesystem.write = ["/home/u/.claude"]
        network.dest.allow = ["api.anthropic.com"]
        systemd.MemoryMax = "1G"
        systemd.Environment = ["A=1"]

        [npm]
        match = "npm"
        filesystem.read = ["/", "/srv/shared"]
        filesystem.write = ["/home/u/.npm"]
        filesystem.deny = ["/srv/secret", "/home/u/.gitconfig"]
        network.dest.allow = ["registry.npmjs.org"]
        systemd.Environment = ["A=1", "B=2"]

        [cargo]
        match = "cargo"
        filesystem.write = ["/srv/shared", "/home/u/.cargo"]
        network.dest.allow = ["*.crates.io", "api.anthropic.com"]
        systemd.MemoryMax = "4G"
    "#;

    #[test]
    fn env_patterns_accumulate_and_are_no_unit_property() {
        let src = r#"
            [base]
            deny_env = "*"
            allow_env = ["A", "B"]

            [npx]
            match = "npx"
            extend = "base"
            allow_env = "B"
            deny_env = "*_TOKEN"

            [sentry]
            match = "npx"
            allow_env = ["SENTRY_*"]
        "#;
        let resolved = resolve(&configs_from_toml(src), "npx", &[]).unwrap();
        assert_eq!(resolved.deny_env, ["*", "*_TOKEN"]);
        assert_eq!(resolved.allow_env, ["A", "B", "SENTRY_*"]);
        // Copying variables alone asks for no sandbox.
        assert_eq!(resolved.systemd_args, Vec::<String>::new());
    }

    #[test]
    fn independent_profiles_combine_on_the_most_permissive_access() {
        let r = selected_args(COMBINED, &["claude", "npm", "cargo"], "zsh");
        assert_eq!(values(&r, "TemporaryFileSystem"), ["/home/u"]);
        assert_eq!(values(&r, "ReadOnlyPaths"), ["-/"]);
        // Read by two of them, written by the third: writable, and only that.
        assert_eq!(values(&r, "ReadWritePaths"), ["-/srv/shared"]);
        assert_eq!(values(&r, "InaccessiblePaths"), ["-/srv/secret"]);
        // Inside the hidden home, everything granted is mounted back in, and a
        // read beats a deny.
        assert_eq!(values(&r, "BindReadOnlyPaths"), ["-/home/u/.gitconfig"]);
        assert_eq!(
            values(&r, "BindPaths"),
            ["-/home/u/.cargo", "-/home/u/.claude", "-/home/u/.npm"]
        );
        assert_eq!(values(&r, "Environment"), ["A=1", "B=2"]);
        assert_eq!(values(&r, "MemoryMax"), ["4G"]);
    }

    #[test]
    fn independent_network_rules_accumulate() {
        let configs = configs_from_toml(COMBINED);
        let names = args(&["claude", "npm", "cargo"]);
        let r = resolve_with(&configs, "zsh", &[], select(&names, false)).unwrap();
        let policy = network_of(r.policies).expect("a network policy");
        assert_eq!(
            policy.dest.allow,
            [
                Destination::Host("api.anthropic.com".to_owned()),
                Destination::Host("registry.npmjs.org".to_owned()),
                Destination::Host("*.crates.io".to_owned()),
            ]
        );
    }

    /// The filesystem lists become mount properties, and nothing else of the table does.
    #[test]
    fn filesystem_lists_become_mount_properties() {
        let r = systemd_args(
            "[curl]\nmatch = \"curl\"\nfilesystem.log = \"denied\"\nfilesystem.read = [\"/x\"]\n",
            "curl",
            &[],
        );
        assert_eq!(r, ["-p", "ReadOnlyPaths=-/x"]);
    }

    fn with_files(files: &FilesystemOverrides) -> ResolveOptions<'_> {
        ResolveOptions {
            filesystem: Some(files),
            ..ResolveOptions::default()
        }
    }

    /// The command line has the last word on a path, and what it writes is
    /// what a broker may hand over.
    #[test]
    fn filesystem_flags_replace_the_profiles_access() {
        let configs = configs_from_toml(
            "[app]\nmatch = \"app\"\nfilesystem.hide = [\"/home/u\"]\n\
             filesystem.write = [\"/srv/x\"]\n",
        );
        let files =
            FilesystemOverrides::parse(&args(&["/srv/x"]), &[], &args(&["/home/u/p"])).unwrap();
        let r = resolve_with(&configs, "app", &[], with_files(&files)).unwrap();
        assert_eq!(
            r.systemd_args,
            [
                "-p",
                "TemporaryFileSystem=/home/u",
                "-p",
                "BindPaths=-/home/u/p",
                "-p",
                "TemporaryFileSystem=/srv/x",
            ]
        );
        assert_eq!(r.writable, [PathBuf::from("/home/u/p")]);
        assert!(
            r.match_log.contains(
                &"filesystem rules from the command line: hide /srv/x; write /home/u/p".to_owned()
            ),
            "{:?}",
            r.match_log
        );

        // With no profile at all, the flags are a sandbox of their own.
        let files = FilesystemOverrides::parse(&[], &args(&["/"]), &[]).unwrap();
        let r = resolve_with(&configs, "other", &[], with_files(&files)).unwrap();
        assert_eq!(r.systemd_args, ["-p", "ReadOnlyPaths=-/"]);
    }

    /// `PrivateTmp=` gives the unit a `/tmp` of its own, where only a bind
    /// mount brings a directory of the host's back.
    #[test]
    fn a_grant_under_a_private_tmp_is_bind_mounted() {
        let profile = "[app]\nmatch = \"app\"\nfilesystem.write = [\"/tmp/claude-1000\"]\n";
        assert_eq!(
            systemd_args(&format!("{profile}systemd.PrivateTmp = true\n"), "app", &[]),
            ["-p", "BindPaths=-/tmp/claude-1000", "-p", "PrivateTmp=yes"]
        );
        assert_eq!(
            systemd_args(profile, "app", &[]),
            ["-p", "ReadWritePaths=-/tmp/claude-1000"]
        );
    }

    #[test]
    fn filesystem_paths_are_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let r = systemd_args(
            "[app]\nmatch = \"app\"\nfilesystem.write = [\"build\", \"$arg_1\"]\n",
            "app",
            &["out/"],
        );
        assert_eq!(
            values(&r, "ReadWritePaths"),
            [
                format!("-{}", cwd.join("build").display()),
                format!("-{}", cwd.join("out").display()),
            ]
        );
    }

    // ── scenario: capturing arguments ─────────────────────────────────────────

    const AGENTS: &str = r#"
        [claude]
        match = "claude"
        args.add_dir = { flags = "--add-dir", greedy = true }
        filesystem.read = ["$arg_add_dir"]

        [myagent]
        match = "myagent"
        args.add_dir = "--add-dir"
        filesystem.read = ["$arg_add_dir"]
    "#;

    #[test]
    fn a_greedy_flag_takes_every_value_after_it() {
        let r = systemd_args(AGENTS, "claude", &["--add-dir", "/a", "/b", "-c"]);
        assert_eq!(values(&r, "ReadOnlyPaths"), ["-/a", "-/b"]);
    }

    #[test]
    fn a_flag_accumulates_across_occurrences_and_forms() {
        let r = systemd_args(
            AGENTS,
            "myagent",
            &[
                "--add-dir",
                "/a",
                "prompt",
                "--add-dir",
                "/b",
                "--add-dir=/c",
            ],
        );
        assert_eq!(values(&r, "ReadOnlyPaths"), ["-/a", "-/b", "-/c"]);
    }

    #[test]
    fn an_absent_flag_adds_nothing() {
        assert!(systemd_args(AGENTS, "claude", &[]).is_empty());
    }

    #[test]
    fn undeclared_flags_take_no_value() {
        let vars = parse_command_args(&args(&["--verbose", "dir", "-x", "f"]), &ArgDecls::new());
        assert_eq!(vars.get("1"), Some(&vec!["dir".to_owned()]));
        assert_eq!(vars.get("2"), Some(&vec!["f".to_owned()]));
        assert_eq!(vars.get("rest"), Some(&vec!["dir f".to_owned()]));
        assert!(!vars.contains_key("verbose"));
    }

    #[test]
    fn a_declared_flag_value_is_not_a_positional() {
        let configs = configs_from_toml("[a]\nargs.target = [\"-t\", \"--target\"]\n");
        let vars = parse_command_args(&args(&["-t", "dir", "file1"]), &configs.0["a"].args);
        assert_eq!(vars.get("target"), Some(&vec!["dir".to_owned()]));
        assert_eq!(vars.get("1"), Some(&vec!["file1".to_owned()]));
    }

    #[test]
    fn double_dash_ends_the_flags() {
        let configs = configs_from_toml("[a]\nargs.x = \"--x\"\n");
        let vars = parse_command_args(&args(&["--", "--x", "p"]), &configs.0["a"].args);
        assert_eq!(vars.get("1"), Some(&vec!["--x".to_owned()]));
        assert_eq!(vars.get("2"), Some(&vec!["p".to_owned()]));
        assert!(!vars.contains_key("x"));
    }

    #[test]
    fn a_multi_valued_argument_replicates_the_template() {
        let r = systemd_args(
            "[app]\nmatch = \"app\"\nargs.inc = \"--inc\"\nsystemd.BindPaths = [\"/always\", \"/p$arg_inc\", \"$arg_missing\"]\n",
            "app",
            &["--inc", "/a", "--inc", "/b"],
        );
        assert_eq!(values(&r, "BindPaths"), ["/always", "/p/a", "/p/b"]);
    }

    #[test]
    fn two_multi_valued_arguments_in_one_template_error() {
        let configs = configs_from_toml(
            "[app]\nmatch = \"app\"\nargs.a = \"--aa\"\nargs.b = \"--bb\"\nsystemd.BindPaths = \"$arg_a/$arg_b\"\n",
        );
        resolve(
            &configs,
            "app",
            &args(&["--aa", "x", "--aa", "y", "--bb", "1", "--bb", "2"]),
        )
        .unwrap_err();
    }

    // ── variables ─────────────────────────────────────────────────────────────

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

    #[test]
    fn a_default_replaces_an_unset_or_empty_variable() {
        // SAFETY: Setting an environment variable is safe here as it is only used for testing.
        unsafe { std::env::set_var("SCUDO_TEST_DEFAULT_SET", "set") }
        // SAFETY: as above.
        unsafe { std::env::set_var("SCUDO_TEST_DEFAULT_EMPTY", "") }
        assert_eq!(
            expand_env("${SCUDO_TEST_DEFAULT_SET:-other}").unwrap(),
            "set"
        );
        assert_eq!(
            expand_env("${SCUDO_TEST_DEFAULT_EMPTY:-other}").unwrap(),
            "other"
        );
        assert_eq!(
            expand_env("${SCUDO_UNDEFINED_XYZ_VAR:-other}/x").unwrap(),
            "other/x"
        );
        assert_eq!(
            expand_env(
                "${SCUDO_UNDEFINED_XYZ_VAR:-${SCUDO_UNDEFINED_ABC_VAR:-$SCUDO_TEST_DEFAULT_SET}}"
            )
            .unwrap(),
            "set"
        );
        assert_eq!(expand_env("${arg_1:-}").unwrap(), "");
        // A default is expanded only when used.
        assert_eq!(
            expand_env("${SCUDO_TEST_DEFAULT_SET:-$SCUDO_UNDEFINED_XYZ_VAR}").unwrap(),
            "set"
        );
        // A `$` starting no reference stays as it is.
        assert_eq!(expand_env("a$ b$1 $").unwrap(), "a$ b$1 $");
        expand_env("${arg_1:-x").unwrap_err();
        expand_env("${:-x}").unwrap_err();
    }

    #[test]
    fn an_argument_default_applies_only_without_the_argument() {
        let src = "[app]\nmatch = \"app\"\nargs.dir = { flags = \"--dir\", greedy = true }\nsystemd.Environment = [\"A=${arg_1:-none}\", \"D=${arg_dir:-$arg_1}\"]\n";
        let args = systemd_args(src, "app", &[]);
        assert_eq!(values(&args, "Environment"), ["A=none", "D="], "{args:?}");
        let args = systemd_args(src, "app", &["pos", "--dir", "x", "--dir", "y"]);
        assert_eq!(
            values(&args, "Environment"),
            ["A=pos", "D=x", "D=y"],
            "{args:?}"
        );
        let args = systemd_args(src, "app", &["pos"]);
        assert_eq!(values(&args, "Environment"), ["A=pos", "D=pos"], "{args:?}");
    }

    #[test]
    fn find_up_returns_the_closest_directory_holding_a_name() {
        let root = std::env::temp_dir().join(format!("scudo-find-up-{}", std::process::id()));
        let nested = root.join("repo/pkg/src/deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(root.join("repo/.git")).unwrap();
        std::fs::write(root.join("repo/pkg/package.json"), "{}").unwrap();
        std::fs::create_dir_all(root.join("worktree/sub")).unwrap();
        std::fs::write(root.join("worktree/.git"), "gitdir: elsewhere\n").unwrap();

        let names = |n: &[&str]| n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let git = names(&[".git"]);
        assert_eq!(find_up(&nested, &git), Some(root.join("repo")));
        assert_eq!(find_up(&root.join("repo"), &git), Some(root.join("repo")));
        // A file counts as much as a directory: a worktree has a `.git` file.
        assert_eq!(
            find_up(&root.join("worktree/sub"), &git),
            Some(root.join("worktree"))
        );
        assert_eq!(
            find_up(&nested, &names(&["package.json"])),
            Some(root.join("repo/pkg"))
        );
        // Any of the names will do, and the closest directory wins.
        assert_eq!(
            find_up(&nested, &names(&[".git", "package.json"])),
            Some(root.join("repo/pkg"))
        );
        assert_eq!(find_up(&nested, &names(&["scudo-no-such-marker"])), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Tests run from the crate root, which holds a `Cargo.toml`.
    const LOOKUP_VARS: &str = r#"
        [scudo-test]
        match = "scudo-test"
        vars.FOUND = { lookup = ["scudo-no-such-marker", "Cargo.toml"] }
        vars.SKIPPED = { lookup = "scudo-no-such-marker" }
        vars.CWD = { lookup = "scudo-no-such-marker", fallback = "cwd" }
        vars.FAILED = { lookup = "scudo-no-such-marker", fallback = "error" }
    "#;

    fn lookup_args(extra: &str) -> Result<Vec<String>> {
        let configs = configs_from_toml(&format!("{LOOKUP_VARS}\n{extra}"));
        Ok(resolve(&configs, "scudo-test", &[])?.systemd_args)
    }

    #[test]
    fn a_lookup_variable_is_the_directory_holding_its_marker() {
        let cwd = std::env::current_dir().unwrap();
        let cwd = cwd.to_string_lossy();
        let args =
            lookup_args("systemd.ReadWritePaths = [\"$FOUND/target\", \"$SKIPPED/sub\", \"$CWD\"]")
                .unwrap();
        assert!(
            has_arg(&args, &format!("ReadWritePaths={cwd}/target")),
            "{args:?}"
        );
        assert!(has_arg(&args, &format!("ReadWritePaths={cwd}")), "{args:?}");
        // Skipped means gone, not an empty prefix that leaves `/sub`.
        assert!(!args.iter().any(|a| a.ends_with("/sub")), "{args:?}");
    }

    #[test]
    fn a_skipped_lookup_variable_drops_a_scalar_property() {
        let args = lookup_args("systemd.WorkingDirectory = \"$SKIPPED\"").unwrap();
        assert!(
            !args.iter().any(|a| a.starts_with("WorkingDirectory=")),
            "{args:?}"
        );
    }

    #[test]
    fn an_error_lookup_variable_fails_only_when_referenced() {
        lookup_args("").unwrap();
        let err = lookup_args("systemd.ReadWritePaths = [\"$FAILED\"]").unwrap_err();
        assert!(
            format!("{err:#}").contains("scudo-no-such-marker"),
            "{err:#}"
        );
    }

    #[test]
    fn a_default_overrides_the_fallback_of_a_lookup_variable() {
        let cwd = std::env::current_dir().unwrap();
        let cwd = cwd.to_string_lossy();
        let args = lookup_args(
            "systemd.ReadWritePaths = [\"${FAILED:-/a}\", \"${SKIPPED:-/b}\", \"${FOUND:-/c}\"]",
        )
        .unwrap();
        assert_eq!(
            values(&args, "ReadWritePaths"),
            ["/a", "/b", &*cwd],
            "{args:?}"
        );
    }

    #[test]
    fn profile_lookup_variables_override_global_ones_and_the_environment() {
        // SAFETY: Setting an environment variable is safe here as it is only used for testing.
        unsafe { std::env::set_var("SCUDO_TEST_LOOKUP", "/from/env") }
        let configs = configs_from_toml(
            r#"
            [a]
            match = "a"
            vars.SCUDO_TEST_LOOKUP = { lookup = "Cargo.toml" }
            systemd.ReadWritePaths = ["$SCUDO_TEST_LOOKUP", "$GLOBAL"]
            "#,
        );
        let global: VarDecls = toml::from_str(
            r#"
            GLOBAL = { lookup = "scudo-no-such-marker", fallback = "cwd" }
            SCUDO_TEST_LOOKUP = { lookup = "scudo-no-such-marker" }
            "#,
        )
        .unwrap();
        let args = resolve_with(
            &configs,
            "a",
            &[],
            ResolveOptions {
                vars: Some(&global),
                ..ResolveOptions::default()
            },
        )
        .unwrap()
        .systemd_args;
        let cwd = std::env::current_dir().unwrap();
        let cwd = cwd.to_string_lossy();
        assert_eq!(
            args.iter()
                .filter(|a| **a == format!("ReadWritePaths={cwd}"))
                .count(),
            2,
            "{args:?}"
        );
    }

    // ── path canonicalization ─────────────────────────────────────────────────

    fn path_args(key: &str, template: &str, command_args: &[&str]) -> Vec<String> {
        systemd_args(
            &format!("[app]\nmatch = \"app\"\nsystemd.{key} = {template:?}\n"),
            "app",
            command_args,
        )
    }

    #[test]
    fn path_env_var_relative_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_PATH", "relative/dir") }
        let expected = cwd.join("relative/dir").to_string_lossy().into_owned();
        assert!(has_arg(
            &path_args("BindPaths", "$SCUDO_TEST_PATH", &[]),
            &format!("BindPaths={expected}")
        ));
    }

    #[test]
    fn path_var_non_path_property_not_canonicalized() {
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_NONPATH", "relative/value") }
        assert!(has_arg(
            &path_args("CPUQuota", "$SCUDO_TEST_NONPATH", &[]),
            "CPUQuota=relative/value"
        ));
    }

    #[test]
    fn a_path_default_is_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let expected = cwd.join("mydir").to_string_lossy().into_owned();
        assert!(has_arg(
            &path_args("BindPaths", "${arg_1:-mydir}", &[]),
            &format!("BindPaths={expected}")
        ));
    }

    #[test]
    fn path_arg_relative_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let expected = cwd.join("mydir").to_string_lossy().into_owned();
        assert!(has_arg(
            &path_args("BindPaths", "$arg_1", &["mydir"]),
            &format!("BindPaths={expected}")
        ));
    }

    #[test]
    fn path_literal_not_touched() {
        assert!(has_arg(
            &path_args("BindPaths", "relative/hardcoded", &[]),
            "BindPaths=relative/hardcoded"
        ));
    }

    #[test]
    fn path_literal_prefix_with_var_relative() {
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_DASH_PATH", "some/dir") }
        let expected = format!("-{}", cwd.join("some/dir").to_string_lossy());
        assert!(has_arg(
            &path_args("ReadWritePaths", "-$SCUDO_TEST_DASH_PATH", &[]),
            &format!("ReadWritePaths={expected}")
        ));
    }

    #[test]
    fn a_var_inside_a_path_component_is_not_made_absolute() {
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_UID", "1000") }
        assert!(has_arg(
            &path_args("ReadWritePaths", "-/tmp/claude-$SCUDO_TEST_UID", &[]),
            "ReadWritePaths=-/tmp/claude-1000"
        ));
    }

    #[test]
    fn each_side_of_a_bind_is_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env vars
        unsafe { std::env::set_var("SCUDO_TEST_BIND_SRC", "src") }
        // SAFETY: test-only env vars
        unsafe { std::env::set_var("SCUDO_TEST_BIND_DST", "dst") }
        let expected = format!(
            "BindPaths=-{}:{}",
            cwd.join("src").to_string_lossy(),
            cwd.join("dst").to_string_lossy()
        );
        assert!(has_arg(
            &path_args(
                "BindPaths",
                "-$SCUDO_TEST_BIND_SRC:$SCUDO_TEST_BIND_DST",
                &[]
            ),
            &expected
        ));
    }

    #[test]
    fn a_var_right_after_an_array_arg_is_not_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        // SAFETY: test-only env var
        unsafe { std::env::set_var("SCUDO_TEST_SUFFIX", "x") }
        let out = systemd_args(
            "[app]\nmatch = \"app\"\nargs.dir = [\"-C\"]\n\
             systemd.BindPaths = \"$arg_dir$SCUDO_TEST_SUFFIX\"\n",
            "app",
            &["-C", "a", "-C", "b"],
        );
        for dir in ["a", "b"] {
            let expected = format!("BindPaths={}x", cwd.join(dir).to_string_lossy());
            assert!(has_arg(&out, &expected), "{expected} not in {out:?}");
        }
    }

    // ── logging, reporting and network ────────────────────────────────────────

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
            match = "*"
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

    // ── network rules from the command line ───────────────────────────────────

    fn overrides(allow_dest: &[&str], deny_dest: &[&str]) -> NetworkOverrides {
        NetworkOverrides::parse(&args(allow_dest), &args(deny_dest), &[], &[]).unwrap()
    }

    fn policies_with(src: &str, command: &str, overrides: &NetworkOverrides) -> Vec<Policy> {
        let configs = configs_from_toml(src);
        resolve_with(
            &configs,
            command,
            &[],
            ResolveOptions {
                network: Some(overrides),
                ..ResolveOptions::default()
            },
        )
        .unwrap()
        .policies
    }

    fn network_of(policies: Vec<Policy>) -> Option<NetworkPolicy> {
        policies.into_iter().find_map(|policy| match policy {
            Policy::Network(network) => Some(network),
            Policy::Filesystem(_) => None,
        })
    }

    #[test]
    fn command_line_rules_apply_over_the_profile() {
        let policy = network_of(policies_with(
            r#"
            [curl]
            match = "curl"
            network.dest.allow = ["1.1.1.1"]
            network.dest.deny = ["10.0.0.0/8"]
            "#,
            "curl",
            &overrides(&["10.0.0.0/8"], &["1.1.1.1"]),
        ))
        .expect("a network policy");
        assert_eq!(
            policy.dest.allow,
            vec![Destination::Net {
                addr: "10.0.0.0".parse().unwrap(),
                prefix_len: 8
            }]
        );
        assert_eq!(
            policy.dest.deny,
            vec![Destination::Net {
                addr: "1.1.1.1".parse().unwrap(),
                prefix_len: 32
            }]
        );
    }

    #[test]
    fn command_line_denies_make_a_policy_where_there_was_none() {
        let policy = network_of(policies_with(
            "[curl]\nmatch = \"curl\"\nsystemd.PrivateTmp = true\n",
            "curl",
            &overrides(&[], &["example.com"]),
        ))
        .expect("a network policy");
        assert_eq!(policy.default, Action::Allow);
        assert!(policy.requires_enforcer());
    }

    #[test]
    fn command_line_rules_that_leave_nothing_restricted_drop_the_policy() {
        let policies = policies_with(
            r#"
            [curl]
            match = "curl"
            network.default = "allow"
            network.inbound = "allow"
            network.dest.deny = ["example.com"]
            "#,
            "curl",
            &overrides(&["example.com"], &[]),
        );
        assert!(network_of(policies).is_none());
    }

    #[test]
    fn command_line_rules_are_logged() {
        let configs = configs_from_toml("[curl]\nmatch = \"curl\"\n");
        let overrides = overrides(&["1.1.1.1"], &[]);
        let resolved = resolve_with(
            &configs,
            "curl",
            &[],
            ResolveOptions {
                network: Some(&overrides),
                ..ResolveOptions::default()
            },
        )
        .unwrap();
        assert!(
            resolved
                .match_log
                .iter()
                .any(|l| l.contains("allow dest 1.1.1.1")),
            "{:?}",
            resolved.match_log
        );
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
            network.dest.allow = ["api.github.com"]
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
            args.host = { flags = "--host", greedy = true }
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
            args.port = { flags = "--port", greedy = true }
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

    const DELEGATING: &str = r#"
        [agent]
        match = "agent"
        filesystem.read = ["/"]
        filesystem.write = ["/srv/agent"]
        delegate = "tool"

        [tool]
        match = "tool"
        delegable = true
        args.dir = ["-C"]
        filesystem.read = ["/", "relative/dir"]
        filesystem.write = ["/srv/cache", "${arg_dir:-$PWD}"]
        systemd.BindPaths = ["/srv/fixed:/srv/fixed", "$PWD/out:/out"]
    "#;

    #[test]
    fn what_is_delegated_and_what_matched_is_reported() {
        let configs = configs_from_toml(DELEGATING);
        let agent = resolve(&configs, "agent", &[]).unwrap();
        assert_eq!(agent.delegate, ["tool"]);
        assert_eq!(agent.matched, ["agent"]);
        assert_eq!(agent.writable, [PathBuf::from("/srv/agent")]);
        // Nothing the agent's own profile grants comes from the request.
        assert_eq!(agent.derived, Vec::<PathBuf>::new());
    }

    /// `$PWD`, an argument and a relative path are the request's to choose;
    /// `/srv/cache` and `/srv/fixed` were written down and are not.
    #[test]
    fn paths_worked_out_from_the_request_are_told_apart() {
        let configs = configs_from_toml(DELEGATING);
        let cwd = std::env::current_dir().unwrap();
        let tool = resolve(&configs, "tool", &args(&["-C", "/elsewhere"])).unwrap();
        assert!(tool.derived.contains(&PathBuf::from("/elsewhere")));
        assert!(tool.derived.contains(&cwd.join("relative/dir")));
        assert!(!tool.derived.contains(&PathBuf::from("/srv/cache")));
        assert!(!tool.derived.contains(&PathBuf::from("/srv/fixed")));
        assert!(tool.derived.contains(&PathBuf::from("/out")));

        let tool = resolve(&configs, "tool", &[]).unwrap();
        // The default stands in for the missing argument, and is `$PWD`.
        let pwd = PathBuf::from(std::env::var("PWD").unwrap());
        assert!(tool.derived.contains(&pwd));
    }

    #[test]
    fn a_lookup_variable_is_the_request_s() {
        let vars = Vars {
            args: ArgVars::new(),
            lookups: [(
                "PROJECT".to_owned(),
                toml::from_str("lookup = \".git\"\nfallback = \"cwd\"").unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        assert!(request_derived("${PROJECT}/target", &vars).unwrap());
        assert!(request_derived("${HOME:-$PROJECT}", &vars).unwrap());
        assert!(!request_derived("$HOME/.cache", &vars).unwrap());
        assert!(!request_derived("-/srv/x", &vars).unwrap());
        assert!(request_derived("-srv/x", &vars).unwrap());
    }
}

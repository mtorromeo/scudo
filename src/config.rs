use std::{env::VarError, path::PathBuf, sync::OnceLock};

use anyhow::{Context as _, Result, bail};
use glob::Pattern;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Deserializer, de};

use crate::{
    logging::LogConfig,
    policy::{FilesystemConfig, NetworkConfig},
    trust,
    tui::TuiConfig,
};

/// A list written as a single string or as an array of them.
fn one_or_many<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    // The untagged enum's own error names the enum rather than what was wrong.
    match OneOrMany::deserialize(de)
        .map_err(|_ignored| de::Error::custom("expected a string or an array of strings"))?
    {
        OneOrMany::One(s) => Ok(vec![s]),
        OneOrMany::Many(v) => Ok(v),
    }
}

/// Maps a `$arg_<name>` variable to the flags that fill it.
pub type ArgDecls = IndexMap<String, ArgDecl>;

/// The flags behind one `$arg_*` variable.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum ArgDecl {
    /// `dir = "--add-dir"`.
    One(String),
    /// `dir = ["-d", "--add-dir"]`.
    Many(Vec<String>),
    /// `dir = { flags = "--add-dir", greedy = true }`.
    Table(ArgTable),
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArgTable {
    #[serde(deserialize_with = "one_or_many")]
    flags: Vec<String>,
    /// Take every argument that follows the flag up to the next one starting
    /// with `-`, rather than only the next one.
    #[serde(default)]
    greedy: bool,
}

impl ArgDecl {
    #[must_use]
    pub fn flags(&self) -> &[String] {
        match self {
            ArgDecl::One(flag) => core::slice::from_ref(flag),
            ArgDecl::Many(flags) | ArgDecl::Table(ArgTable { flags, .. }) => flags,
        }
    }

    #[must_use]
    pub fn is_greedy(&self) -> bool {
        matches!(self, ArgDecl::Table(ArgTable { greedy: true, .. }))
    }
}

/// Maps a lookup variable's name to how it is found.
pub type VarDecls = IndexMap<String, VarDecl>;

/// A variable naming the closest directory, from the current one up, that
/// holds one of `lookup`.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VarDecl {
    /// File or directory names; the first directory holding any of them wins.
    #[serde(deserialize_with = "one_or_many")]
    pub lookup: Vec<String>,
    #[serde(default)]
    pub fallback: Fallback,
}

/// What a lookup variable is when no directory holds what it looks for.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// Nothing: the value referencing it is dropped, as if never written.
    #[default]
    Skip,
    /// The current directory.
    Cwd,
    /// The command does not run.
    Error,
}

/// Check the names a `vars` table declares and what they look for, so a
/// mistake is reported when the config is read.
fn validate_vars(vars: &VarDecls) -> Result<()> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new("^[A-Za-z_][A-Za-z0-9_]*$").expect("regex is valid"));
    for (name, decl) in vars {
        if !re.is_match(name) || name.starts_with("arg_") || name == CONFIG_DIR_VAR {
            bail!("vars: '{name}' is not a valid variable name");
        }
        if decl.lookup.is_empty() {
            bail!("vars.{name}: lookup names nothing");
        }
        for entry in &decl.lookup {
            let path = std::path::Path::new(entry);
            if entry.is_empty()
                || path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("vars.{name}: '{entry}' must be a relative name inside a directory");
            }
        }
    }
    Ok(())
}

/// A profile as written in TOML. Systemd unit properties live in the `systemd`
/// sub-table rather than at the top level, so every other key is one this struct
/// knows about and a misspelled one is an error instead of a silently ignored
/// property.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Globs on the command name; any one of them matching is enough. Empty:
    /// the profile is reachable only through `extend` or `--profile`.
    #[serde(rename = "match", default, deserialize_with = "one_or_many")]
    pub r#match: Vec<String>,
    /// Profiles applied before this one.
    #[serde(default, deserialize_with = "one_or_many")]
    pub extend: Vec<String>,
    /// Whether this profile adds to a same-named one from a lower-priority
    /// config file (the default) or replaces it.
    pub inherit: Option<bool>,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    /// The `$arg_*` variables filled from the command's flags.
    #[serde(default)]
    pub args: ArgDecls,
    /// Variables found by looking up the directory tree.
    #[serde(default)]
    pub vars: VarDecls,
    /// Network policy, kept in its raw form so that its lists can be merged
    /// before anything in them is expanded.
    #[serde(default)]
    pub network: Option<toml::Table>,
    /// The `[<profile>.filesystem]` sub-table: path access, and whether the
    /// sandbox says which paths its restrictions turned away.
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    /// The `[<profile>.log]` sub-table: level and destination.
    #[serde(default)]
    pub log: LogConfig,
    /// The `[<profile>.systemd]` sub-table: unit properties keyed by their exact
    /// systemd name. Values are either a single string/bool/integer or an array
    /// thereof. Keeping them in a table of their own is what lets the profile's
    /// own keys be checked for typos — see `deny_unknown_fields` above.
    #[serde(default)]
    pub systemd: toml::Table,
}

pub type ConfigMap = IndexMap<String, ProfileConfig>;

/// The name of the reserved table, which is therefore not a profile name.
pub const SETTINGS_SECTION: &str = "scudo";

/// The `[scudo]` table: what holds for scudo itself rather than for one command.
///
/// It is the *lowest* priority source for everything it carries, sitting under
/// the profiles and under the command line. That is what makes it a default
/// rather than an override: a profile can still be quieter than it, which a
/// setting that won would not allow.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Default level and destination for scudo's own output.
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub tui: TuiConfig,
    /// Lookup variables every profile can reference.
    #[serde(default)]
    pub vars: VarDecls,
}

impl Settings {
    /// Fields set on `self` win; the rest fall back to `lower`. Used to layer
    /// the config files over each other in priority order.
    #[must_use]
    fn over(self, lower: Self) -> Self {
        let mut vars = lower.vars;
        vars.extend(self.vars);
        Settings {
            log: self.log.over(lower.log),
            tui: self.tui.over(lower.tui),
            vars,
        }
    }
}

/// Everything the config files had to say.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub profiles: ValidatedConfigMap,
    pub settings: Settings,
}

/// A profile once its patterns are compiled and its tables checked.
///
/// Profiles combine one way only, whatever brought them together — `extend`,
/// matching the same command, `--profile`, or sharing a name across config
/// files: see [`Profile::merge`].
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub patterns: Vec<Pattern>,
    pub extend: Vec<String>,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    pub args: ArgDecls,
    pub vars: VarDecls,
    pub network: Option<toml::Table>,
    pub filesystem: FilesystemConfig,
    pub log: LogConfig,
    pub systemd: toml::Table,
}

impl Profile {
    /// Apply `other` on top of `self`.
    ///
    /// Lists accumulate, without repeating an entry; everything else is taken
    /// from `other` when it says anything. That is what lets profiles written
    /// without knowing about each other be combined: none of them can take
    /// away what another one added.
    pub fn merge(&mut self, other: &Profile) {
        union(&mut self.patterns, &other.patterns);
        union(&mut self.extend, &other.extend);
        self.exec = other.exec.clone().or(self.exec.take());
        self.verbose = other.verbose.or(self.verbose);
        self.confirm = other.confirm.or(self.confirm);
        self.args
            .extend(other.args.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.vars
            .extend(other.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
        if let Some(network) = &other.network {
            merge_table(self.network.get_or_insert_default(), network);
        }
        self.filesystem = other
            .filesystem
            .clone()
            .over(core::mem::take(&mut self.filesystem));
        self.log = other.log.clone().over(core::mem::take(&mut self.log));
        merge_table(&mut self.systemd, &other.systemd);
    }

    fn validate(name: &str, config: ProfileConfig) -> Result<Profile> {
        if config.extend.iter().any(|e| e == name) {
            bail!(
                "profile '{name}': a profile no longer needs to extend itself, \
                 it inherits from the same-named one in lower-priority files on its own \
                 (`inherit = false` replaces it instead)"
            );
        }
        let lists = config
            .r#match
            .iter()
            .chain(&config.extend)
            .chain(&config.filesystem.write)
            .chain(&config.filesystem.read)
            .chain(&config.filesystem.hide)
            .chain(&config.filesystem.deny);
        let in_tables = |table: &toml::Table| table.values().any(holds_sentinel);
        if lists.into_iter().any(|e| e == SENTINEL)
            || in_tables(&config.systemd)
            || config.network.as_ref().is_some_and(in_tables)
        {
            bail!(
                "profile '{name}': '{SENTINEL}' is no longer needed, \
                 lists always add to what they inherit"
            );
        }
        if let Some(table) = &config.network {
            validate_network(name, table)?;
        }
        validate_vars(&config.vars).with_context(|| format!("profile '{name}'"))?;
        let patterns = config
            .r#match
            .iter()
            .map(|p| {
                Pattern::new(p)
                    .with_context(|| format!("profile '{name}': invalid match pattern '{p}'"))
            })
            .collect::<Result<_>>()?;
        Ok(Profile {
            patterns,
            extend: config.extend,
            exec: config.exec,
            verbose: config.verbose,
            confirm: config.confirm,
            args: config.args,
            vars: config.vars,
            network: config.network,
            filesystem: config.filesystem,
            log: config.log,
            systemd: config.systemd,
        })
    }
}

/// What used to splice an inherited list in. Lists now always accumulate, so
/// finding it means a config written for the old rules.
const SENTINEL: &str = "...";

fn holds_sentinel(value: &toml::Value) -> bool {
    match value {
        toml::Value::Array(items) => items
            .iter()
            .any(|v| v.as_str() == Some(SENTINEL) || holds_sentinel(v)),
        toml::Value::Table(table) => table.values().any(holds_sentinel),
        toml::Value::String(_)
        | toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => false,
    }
}

fn union<T: PartialEq + Clone>(base: &mut Vec<T>, extra: &[T]) {
    for item in extra {
        if !base.contains(item) {
            base.push(item.clone());
        }
    }
}

/// Merge `src` into `dst`: arrays accumulate, tables merge key by key, and
/// anything else is replaced.
fn merge_table(dst: &mut toml::Table, src: &toml::Table) {
    for (key, value) in src {
        match (dst.get_mut(key), value) {
            (Some(toml::Value::Array(base)), toml::Value::Array(extra)) => union(base, extra),
            (Some(toml::Value::Table(base)), toml::Value::Table(extra)) => {
                merge_table(base, extra);
            }
            _ => {
                dst.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Every profile, in the order they were defined: files from the lowest
/// priority to the highest, then by position within the file. A profile
/// redefined by a later file keeps its first position.
#[derive(Debug, Clone, Default)]
pub struct ValidatedConfigMap(pub IndexMap<String, Profile>);

impl ValidatedConfigMap {
    /// Add one config file's profiles on top of what is already loaded.
    fn layer(&mut self, configs: ConfigMap) -> Result<()> {
        for (name, config) in configs {
            let inherit = config.inherit.unwrap_or(true);
            let profile = Profile::validate(&name, config)?;
            match self.0.get_mut(&name) {
                Some(existing) if inherit => existing.merge(&profile),
                _ => {
                    self.0.insert(name, profile);
                }
            }
        }
        Ok(())
    }
}

impl TryFrom<ConfigMap> for ValidatedConfigMap {
    type Error = anyhow::Error;

    fn try_from(value: ConfigMap) -> Result<Self> {
        let mut map = ValidatedConfigMap::default();
        map.layer(value)?;
        Ok(map)
    }
}

/// Check a profile's `network` table parses, so a typo is reported when the
/// config is read rather than when a command is about to run.
fn validate_network(name: &str, table: &toml::Table) -> Result<()> {
    let config: NetworkConfig = toml::Value::Table(table.clone())
        .try_into()
        .with_context(|| format!("profile '{name}': invalid network policy"))?;
    config
        .validate()
        .with_context(|| format!("profile '{name}': invalid network policy"))
}

/// The variable name that expands to the directory containing the config file a
/// profile was defined in. Scudo-namespaced and uppercase to minimise the chance
/// of colliding with a real environment variable.
const CONFIG_DIR_VAR: &str = "SCUDO_CONFIG_DIR";

/// Replace `$SCUDO_CONFIG_DIR` / `${SCUDO_CONFIG_DIR}` references in `s` with `dir`.
///
/// The `$SCUDO_CONFIG_DIR` (unbraced) form uses a trailing word boundary so it
/// won't swallow a longer identifier such as `$SCUDO_CONFIG_DIRECTORY`. Uses a
/// replacement closure so any `$` in `dir` is treated literally rather than as a
/// capture reference.
fn substitute_config_dir_str(s: &str, dir: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(&format!(r"\$\{{{CONFIG_DIR_VAR}\}}|\${CONFIG_DIR_VAR}\b"))
            .expect("regex is valid")
    });
    re.replace_all(s, |_: &regex::Captures| dir.to_owned())
        .into_owned()
}

/// Recursively substitute `$SCUDO_CONFIG_DIR` in every string within `value`.
fn substitute_config_dir(value: &mut toml::Value, dir: &str) {
    match value {
        toml::Value::String(s) => {
            if s.contains(CONFIG_DIR_VAR) {
                *s = substitute_config_dir_str(s, dir);
            }
        }
        toml::Value::Array(arr) => {
            for item in arr {
                substitute_config_dir(item, dir);
            }
        }
        toml::Value::Table(table) => {
            for (_, item) in table.iter_mut() {
                substitute_config_dir(item, dir);
            }
        }
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
}

/// Substitute the config-dir variable in all of a profile's string values.
///
/// Done eagerly, per config file, because once profiles from different files are
/// merged (by name, via `extend`, or by matching together) we can no longer tell which file a
/// given property came from.
fn substitute_profile_config_dir(profile: &mut ProfileConfig, dir: &str) {
    for (_, value) in &mut profile.systemd {
        substitute_config_dir(value, dir);
    }
    let fs = &mut profile.filesystem;
    for path in fs
        .write
        .iter_mut()
        .chain(fs.read.iter_mut())
        .chain(fs.hide.iter_mut())
        .chain(fs.deny.iter_mut())
    {
        if path.contains(CONFIG_DIR_VAR) {
            *path = substitute_config_dir_str(path, dir);
        }
    }
    if let Some(network) = profile.network.as_mut() {
        for (_, value) in network.iter_mut() {
            substitute_config_dir(value, dir);
        }
    }
    if let Some(exec) = profile.exec.as_mut()
        && exec.contains(CONFIG_DIR_VAR)
    {
        *exec = substitute_config_dir_str(exec, dir);
    }
    if let Some(path) = profile.log.path.as_mut()
        && path.contains(CONFIG_DIR_VAR)
    {
        *path = substitute_config_dir_str(path, dir);
    }
}

/// Substitute `$SCUDO_CONFIG_DIR` in the reserved table, which reaches only the
/// log path — the other settings name keys and sizes, never paths.
fn substitute_settings_config_dir(settings: &mut Settings, dir: &str) {
    if let Some(path) = settings.log.path.as_mut()
        && path.contains(CONFIG_DIR_VAR)
    {
        *path = substitute_config_dir_str(path, dir);
    }
}

/// Take the reserved `[scudo]` table out of a parsed file, leaving the profiles.
///
/// Splitting the table by hand rather than with `#[serde(flatten)]` is what
/// keeps `deny_unknown_fields` working on `ProfileConfig`: flattening turns
/// every unknown profile key into a candidate for the outer struct, and a typo
/// would stop being an error.
fn split_settings(mut table: toml::Table, path: &std::path::Path) -> Result<(ConfigMap, Settings)> {
    let settings = match table.remove(SETTINGS_SECTION) {
        Some(value) => value
            .try_into::<Settings>()
            .with_context(|| format!("parsing [{SETTINGS_SECTION}] in {}", path.display()))?,
        None => Settings::default(),
    };
    validate_vars(&settings.vars)
        .with_context(|| format!("in [{SETTINGS_SECTION}] in {}", path.display()))?;
    let profiles = toml::Value::Table(table)
        .try_into::<ConfigMap>()
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok((profiles, settings))
}

/// Load and merge configs from all search paths (lowest to highest priority).
pub fn load_configs() -> Result<Loaded> {
    let mut profiles = ValidatedConfigMap::default();
    let mut settings = Settings::default();
    for path in config_search_paths() {
        if !path.is_file() {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        if path.file_name().is_some_and(|n| n == ".scudo.toml") {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            trust::check_and_confirm(&canonical, &content)?;
        }

        let table: toml::Table =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        let (mut file_configs, mut file_settings) = split_settings(table, &path)?;

        // Directory containing this config file — the value of `$SCUDO_CONFIG_DIR`
        // for every profile defined in it.
        let config_dir = path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        substitute_settings_config_dir(&mut file_settings, &config_dir);
        settings = file_settings.over(settings);

        for profile in file_configs.values_mut() {
            substitute_profile_config_dir(profile, &config_dir);
        }
        profiles
            .layer(file_configs)
            .with_context(|| format!("in {}", path.display()))?;
    }
    Ok(Loaded { profiles, settings })
}

pub fn user_path() -> Result<PathBuf, VarError> {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| match std::env::var("HOME") {
            Ok(home) => Ok(PathBuf::from(home).join(".config")),
            Err(err) => Err(err),
        })
        .map(|p| p.join("scudo"))
}

fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    paths.push(PathBuf::from("/etc/scudo/config.toml"));

    if let Ok(path) = user_path() {
        paths.push(path.join("config.toml"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        let mut local: Vec<PathBuf> = cwd.ancestors().map(|dir| dir.join(".scudo.toml")).collect();
        local.reverse(); // root first → $PWD last (highest priority)
        paths.extend(local);
    }

    paths
}

#[cfg(test)]
#[expect(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Parse one config file the way `load_configs` does.
    fn split(src: &str) -> Result<(ConfigMap, Settings)> {
        let table: toml::Table = toml::from_str(src)?;
        split_settings(table, std::path::Path::new("test.toml"))
    }

    #[test]
    fn the_reserved_table_is_taken_out_and_the_rest_are_profiles() {
        let (profiles, settings) = split(
            r#"
            [scudo]
            log.level = "info"
            tui.prefix = "C-b"
            tui.scrollback = 20000

            [curl]
            match = "curl"
            systemd.MemoryMax = "256M"
            "#,
        )
        .expect("the file parses");

        assert_eq!(settings.log.level, Some(crate::logging::Level::Info));
        assert_eq!(settings.tui.prefix(), "C-b");
        assert_eq!(settings.tui.scrollback(), 20000);
        // `scudo` is settings, not a profile that happens to be named that.
        assert_eq!(profiles.len(), 1);
        assert!(profiles.contains_key("curl"));
    }

    /// The section is optional, and a config without it is every config written
    /// before it existed.
    #[test]
    fn a_config_without_the_reserved_table_still_parses() {
        let (profiles, settings) = split("[curl]\nmatch = \"curl\"\n").expect("the file parses");
        assert_eq!(settings, Settings::default());
        assert_eq!(profiles.len(), 1);
    }

    /// A typo in the reserved table has to be an error, or the setting silently
    /// does nothing and the fault shows up as behaviour rather than a message.
    #[test]
    fn a_typo_in_the_reserved_table_is_reported_against_it() {
        let err = split("[scudo]\ntui.prefx = \"C-b\"\n").expect_err("the typo is caught");
        let message = format!("{err:#}");
        assert!(message.contains("[scudo]"), "{message}");
        assert!(message.contains("prefx"), "{message}");
    }

    /// The reserved name is not a profile, so a profile key inside it is a
    /// mistake rather than a profile definition.
    #[test]
    fn the_reserved_table_does_not_accept_profile_keys() {
        split("[scudo]\nmatch = \"scudo\"\n").expect_err("a profile key is not a setting");
    }

    /// Same priority order as everything else: the file read last wins, key by
    /// key, so a user config can change the prefix without restating the level.
    #[test]
    fn a_higher_priority_file_overrides_only_what_it_mentions() {
        let lower = Settings {
            log: LogConfig {
                level: Some(crate::logging::Level::Warn),
                ..LogConfig::default()
            },
            tui: TuiConfig {
                prefix: Some("C-a".to_owned()),
                scrollback: Some(30_000),
            },
            ..Settings::default()
        };
        let higher = Settings {
            tui: TuiConfig {
                prefix: Some("C-b".to_owned()),
                ..TuiConfig::default()
            },
            ..Settings::default()
        };
        let merged = higher.over(lower);
        assert_eq!(merged.tui.prefix(), "C-b");
        assert_eq!(merged.tui.scrollback(), 30_000);
        assert_eq!(merged.log.level, Some(crate::logging::Level::Warn));
    }

    /// Load config files the way `load_configs` does, lowest priority first.
    fn load(files: &[&str]) -> ValidatedConfigMap {
        let mut map = ValidatedConfigMap::default();
        for src in files {
            let (profiles, _) = split(src).unwrap();
            map.layer(profiles).unwrap();
        }
        map
    }

    fn profile_error(src: &str) -> String {
        let (profiles, _) = split(src).unwrap();
        format!("{:#}", ValidatedConfigMap::try_from(profiles).unwrap_err())
    }

    #[test]
    fn absent_match_never_matches() {
        let map = load(&["[curl]\nsystemd.MemoryMax = \"256M\"\n"]);
        assert!(map.0["curl"].patterns.is_empty());
    }

    #[test]
    fn match_takes_one_glob_or_several() {
        let map = load(&["[a]\nmatch = \"curl\"\n[b]\nmatch = [\"zed\", \"code*\"]\n"]);
        assert_eq!(map.0["a"].patterns.len(), 1);
        assert!(map.0["b"].patterns.iter().any(|p| p.matches("code-oss")));
    }

    #[test]
    fn invalid_pattern_is_reported() {
        assert!(profile_error("[curl]\nmatch = \"[\"\n").contains("invalid match pattern"));
    }

    /// Systemd properties belong in the `systemd` sub-table, so a stray key at
    /// the top level is a typo (or the pre-`systemd` layout) rather than a
    /// property — and saying so beats silently dropping it.
    #[test]
    fn unknown_profile_key_is_rejected() {
        for key in [
            "MemoryMax = \"256M\"",
            "final = true",
            "arg_flags = [\"-p\"]",
        ] {
            split(&format!("[curl]\n{key}\n")).expect_err(key);
        }
        split("[curl]\nmatch = { pattern = \"curl\", type = \"glob\" }\n")
            .expect_err("the table form of match is gone");
    }

    /// Profiles are kept in the order they were written, which is the order
    /// they are applied in when several match.
    #[test]
    fn definition_order_is_kept() {
        let map = load(&["[b]\n[a]\n[c]\n", "[d]\n[a]\n"]);
        let names: Vec<&str> = map.0.keys().map(String::as_str).collect();
        assert_eq!(names, ["b", "a", "c", "d"]);
    }

    /// A same-named profile in a higher-priority file adds to the one below:
    /// lists accumulate, and what it says itself wins.
    #[test]
    fn a_same_named_profile_inherits_by_default() {
        let map = load(&[
            "[cargo]\nmatch = \"cargo\"\nconfirm = true\nfilesystem.read = [\"/a\"]\nsystemd.MemoryMax = \"1G\"\n",
            "[cargo]\nfilesystem.read = [\"/b\"]\nsystemd.MemoryMax = \"2G\"\n",
        ]);
        let cargo = &map.0["cargo"];
        assert_eq!(cargo.patterns.len(), 1);
        assert_eq!(cargo.confirm, Some(true));
        assert_eq!(cargo.filesystem.read, ["/a", "/b"]);
        assert_eq!(
            cargo.systemd.get("MemoryMax"),
            Some(&toml::Value::String("2G".to_owned()))
        );
    }

    #[test]
    fn inherit_false_replaces_the_profile() {
        let map = load(&[
            "[cargo]\nmatch = \"cargo\"\nconfirm = true\nfilesystem.read = [\"/a\"]\n",
            "[cargo]\ninherit = false\nfilesystem.read = [\"/b\"]\n",
        ]);
        let cargo = &map.0["cargo"];
        assert!(cargo.patterns.is_empty());
        assert_eq!(cargo.confirm, None);
        assert_eq!(cargo.filesystem.read, ["/b"]);
    }

    /// Configs written for the old rules say so, rather than silently
    /// meaning something else now.
    #[test]
    fn the_old_sentinel_is_reported() {
        for src in [
            "[a]\nsystemd.BindPaths = [\"...\", \"/x\"]\n",
            "[a]\nnetwork.dest.allow = [\"...\"]\n",
            "[a]\nfilesystem.read = [\"...\"]\n",
            "[a]\nmatch = [\"...\", \"a\"]\n",
        ] {
            assert!(profile_error(src).contains("no longer needed"), "{src}");
        }
    }

    #[test]
    fn extending_itself_is_reported() {
        assert!(profile_error("[a]\nextend = \"a\"\n").contains("inherit"));
    }

    #[test]
    fn arguments_are_declared_by_flag() {
        let map = load(&[r#"
            [claude]
            args.one = "--one"
            args.many = ["-m", "--many"]
            args.greedy = { flags = "--add-dir", greedy = true }
        "#]);
        let args = &map.0["claude"].args;
        assert_eq!(args["one"].flags(), ["--one"]);
        assert_eq!(args["many"].flags(), ["-m", "--many"]);
        assert!(!args["many"].is_greedy());
        assert!(args["greedy"].is_greedy());
    }

    #[test]
    fn lookup_variables_are_declared_in_profiles_and_settings() {
        let (profiles, settings) = split(
            r#"
            [scudo]
            vars.GIT_ROOT = { lookup = ".git" }

            [node]
            vars.NODE_ROOT = { lookup = ["package.json", "deno.json"], fallback = "cwd" }
            "#,
        )
        .unwrap();
        assert_eq!(settings.vars["GIT_ROOT"].lookup, [".git"]);
        assert_eq!(settings.vars["GIT_ROOT"].fallback, Fallback::Skip);
        let node = &profiles["node"].vars["NODE_ROOT"];
        assert_eq!(node.lookup, ["package.json", "deno.json"]);
        assert_eq!(node.fallback, Fallback::Cwd);
    }

    #[test]
    fn a_later_definition_of_a_lookup_variable_wins() {
        let map = load(&[
            "[a]\nvars.ROOT = { lookup = \".git\" }\n",
            "[a]\nvars.ROOT = { lookup = \"Cargo.toml\", fallback = \"error\" }\n",
        ]);
        assert_eq!(map.0["a"].vars["ROOT"].lookup, ["Cargo.toml"]);
        assert_eq!(map.0["a"].vars["ROOT"].fallback, Fallback::Error);

        let (_, lower) =
            split("[scudo]\nvars.A = { lookup = \"a\" }\nvars.B = { lookup = \"b\" }\n").unwrap();
        let (_, higher) = split("[scudo]\nvars.B = { lookup = \"c\" }\n").unwrap();
        let merged = higher.over(lower);
        assert_eq!(merged.vars["A"].lookup, ["a"]);
        assert_eq!(merged.vars["B"].lookup, ["c"]);
    }

    #[test]
    fn invalid_lookup_variables_are_reported() {
        for decl in [
            "vars.arg_x = { lookup = \".git\" }",
            "vars.SCUDO_CONFIG_DIR = { lookup = \".git\" }",
            "vars.\"1X\" = { lookup = \".git\" }",
            "vars.X = { lookup = [] }",
            "vars.X = { lookup = \"\" }",
            "vars.X = { lookup = \"/etc\" }",
            "vars.X = { lookup = \"../up\" }",
        ] {
            let (profiles, _) = split(&format!("[a]\n{decl}\n")).unwrap();
            ValidatedConfigMap::try_from(profiles).expect_err(decl);
            split(&format!("[scudo]\n{decl}\n")).expect_err(decl);
        }
        for decl in [
            "vars.X = { lookup = \".git\", fallbak = \"cwd\" }",
            "vars.X = { lookup = \".git\", fallback = \"nope\" }",
        ] {
            split(&format!("[a]\n{decl}\n")).expect_err(decl);
        }
    }

    #[test]
    fn config_dir_substitution() {
        // The unbraced and braced forms both expand; a longer identifier that
        // merely starts with the variable name is left untouched.
        assert_eq!(
            substitute_config_dir_str("$SCUDO_CONFIG_DIR/bin", "/etc/scudo"),
            "/etc/scudo/bin"
        );
        assert_eq!(
            substitute_config_dir_str("${SCUDO_CONFIG_DIR}/bin", "/etc/scudo"),
            "/etc/scudo/bin"
        );
        assert_eq!(
            substitute_config_dir_str("$SCUDO_CONFIG_DIRECTORY", "/etc/scudo"),
            "$SCUDO_CONFIG_DIRECTORY"
        );
    }

    #[test]
    fn config_dir_substitution_in_profile() {
        let mut props = toml::Table::new();
        props.insert(
            "BindReadOnlyPaths".to_owned(),
            toml::Value::Array(vec![
                toml::Value::String("$SCUDO_CONFIG_DIR/allow.txt".to_owned()),
                toml::Value::String("/other".to_owned()),
            ]),
        );
        let mut profile = ProfileConfig {
            exec: Some("$SCUDO_CONFIG_DIR/wrapper.sh".to_owned()),
            systemd: props,
            ..Default::default()
        };

        substitute_profile_config_dir(&mut profile, "/home/user");

        assert_eq!(
            profile.systemd.get("BindReadOnlyPaths"),
            Some(&toml::Value::Array(vec![
                toml::Value::String("/home/user/allow.txt".to_owned()),
                toml::Value::String("/other".to_owned()),
            ]))
        );
        assert_eq!(profile.exec.as_deref(), Some("/home/user/wrapper.sh"));
    }
}

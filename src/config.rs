use std::{collections::HashMap, env::VarError, path::PathBuf, sync::OnceLock};

use anyhow::{Context as _, Result};
use glob::Pattern;
use regex::Regex;
use serde::{Deserialize, Deserializer};

pub type ArgAliases = HashMap<String, ArgAliasDecl>;

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ArgAliasDecl {
    /// Simple form: `foo = ["-f", "--foo"]`.
    Simple(Vec<String>),
    /// Extended form: `foo = { flags = ["-f", "--foo"], nargs = "+" }`.
    Extended {
        flags: Vec<String>,
        nargs: Option<String>,
    },
}

impl ArgAliasDecl {
    #[must_use]
    pub fn flags(&self) -> &[String] {
        match self {
            ArgAliasDecl::Simple(v) => v,
            ArgAliasDecl::Extended { flags, .. } => flags,
        }
    }

    /// Returns `true` if this alias consumes all following non-flag args as values.
    #[must_use]
    pub fn is_multi_value(&self) -> bool {
        matches!(self, ArgAliasDecl::Extended { nargs: Some(n), .. } if n == "+")
    }
}

fn deserialize_extend<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    match OneOrMany::deserialize(de)? {
        OneOrMany::One(s) => Ok(vec![s]),
        OneOrMany::Many(v) => Ok(v),
    }
}

use crate::{
    logging::LogConfig,
    policy::{FilesystemConfig, NetworkConfig},
    trust,
    tui::TuiConfig,
};

/// Match type for a pattern entry. Defaults to `exact` when unspecified.
#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    #[default]
    Exact,
    Glob,
    Regex,
}

/// What a pattern is compared against.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MatchTarget {
    /// Compare against the command name only (default).
    #[default]
    Command,
    /// Compare against the full command line: command name and all arguments joined with spaces.
    FullCommand,
}

/// Compiled match pattern stored on a validated profile.
/// `Sentinel` represents `"..."` — replaced with the parent profile's patterns at resolve time.
#[derive(Debug, Clone)]
pub enum CommandPattern {
    Exact(String, MatchTarget),
    Regex(Regex, MatchTarget),
    Glob(Pattern, MatchTarget),
    /// `"..."` — splices the first parent's patterns in at this position during resolve.
    Sentinel,
}

/// A single raw match entry as written in TOML.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum MatchEntry {
    /// Bare string: `"curl"` → exact match against command name; `"..."` → Sentinel.
    Simple(String),
    /// Table form: `{ pattern = "curl*", type = "glob", target = "full_command" }`.
    Extended {
        pattern: Option<String>,
        #[serde(rename = "type", default)]
        match_type: MatchType,
        #[serde(default)]
        target: MatchTarget,
    },
}

/// Deserialize the `match` field.
///
/// - field absent → `None`  (serde `default` handles this; the profile never matches)
/// - single entry → `Some(vec![entry])`
/// - array        → `Some(entries)`
fn deserialize_match_field<'de, D>(de: D) -> Result<Option<Vec<MatchEntry>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MatchDecl {
        One(MatchEntry),
        Many(Vec<MatchEntry>),
    }
    let decl = MatchDecl::deserialize(de)?;
    Ok(Some(match decl {
        MatchDecl::One(e) => vec![e],
        MatchDecl::Many(v) => v,
    }))
}

/// A profile as written in TOML. Systemd unit properties live in the `systemd`
/// sub-table rather than at the top level, so every other key is one this struct
/// knows about and a misspelled one is an error instead of a silently ignored
/// property.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// `None` = absent: the profile never matches a command on its own and is
    /// reachable only through `extend` or `--profile`.
    /// `Some([…])` = match with the listed pattern(s).
    #[serde(
        rename = "match",
        default,
        deserialize_with = "deserialize_match_field"
    )]
    pub r#match: Option<Vec<MatchEntry>>,
    /// Profiles to inherit from, in left-to-right order (later entries take precedence).
    /// Accepts a single string or an array. Including this profile's own name extends from
    /// the same-named profile in lower-priority config files.
    #[serde(default, deserialize_with = "deserialize_extend")]
    pub extend: Vec<String>,
    /// When `true`, prevents this profile from being used as a base by a higher-priority
    /// config file that self-extends (the self-extend is silently dropped).
    /// Higher-priority files can still replace this profile outright.
    #[serde(default)]
    pub r#final: bool,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    /// Maps variable names to the flag(s) that populate them.
    #[serde(default)]
    pub arg_aliases: ArgAliases,
    /// Flags that take no value (boolean flags); prevents consuming the next arg.
    #[serde(default)]
    pub arg_flags: Vec<String>,
    /// Network policy, kept in its raw form so that `extend` can merge it field
    /// by field with the same array semantics as every other property.
    #[serde(default)]
    pub network: Option<toml::Table>,
    /// The `[<profile>.filesystem]` sub-table: whether the sandbox says which
    /// paths its restrictions turned away. Parsed here rather than kept raw for
    /// the same reason as `log` — it holds no lists to splice.
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    /// The `[<profile>.log]` sub-table: level and destination. Unlike `network`
    /// it holds no lists, so there is no `"..."` splicing to preserve and it can
    /// be parsed into its final shape here rather than merged as raw TOML.
    #[serde(default)]
    pub log: LogConfig,
    /// The `[<profile>.systemd]` sub-table: unit properties keyed by their exact
    /// systemd name. Values are either a single string/bool/integer or an array
    /// thereof. Keeping them in a table of their own is what lets the profile's
    /// own keys be checked for typos — see `deny_unknown_fields` above.
    #[serde(default)]
    pub systemd: HashMap<String, toml::Value>,
}

pub type ConfigMap = HashMap<String, ProfileConfig>;

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
}

impl Settings {
    /// Fields set on `self` win; the rest fall back to `lower`. Used to layer
    /// the config files over each other in priority order.
    #[must_use]
    fn over(self, lower: Self) -> Self {
        Settings {
            log: self.log.over(lower.log),
            tui: self.tui.over(lower.tui),
        }
    }
}

/// Everything the config files had to say.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub profiles: ValidatedConfigMap,
    pub settings: Settings,
}

#[derive(Debug, Clone)]
pub struct ValidatedProfileConfig {
    pub pattern: Vec<CommandPattern>,
    pub extend: Vec<String>,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    pub arg_aliases: ArgAliases,
    pub arg_flags: Vec<String>,
    pub network: Option<toml::Table>,
    pub filesystem: FilesystemConfig,
    pub log: LogConfig,
    pub properties: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone)]
pub struct ValidatedConfigMap(pub HashMap<String, ValidatedProfileConfig>);

impl TryFrom<ConfigMap> for ValidatedConfigMap {
    type Error = anyhow::Error;

    fn try_from(value: ConfigMap) -> Result<Self> {
        let map = value
            .into_iter()
            .map(|(name, config)| {
                let pattern = build_patterns(&name, config.r#match)?;
                if let Some(table) = &config.network {
                    validate_network(&name, table)?;
                }
                Ok((
                    name,
                    ValidatedProfileConfig {
                        pattern,
                        extend: config.extend,
                        exec: config.exec,
                        verbose: config.verbose,
                        confirm: config.confirm,
                        arg_aliases: config.arg_aliases,
                        arg_flags: config.arg_flags,
                        network: config.network,
                        filesystem: config.filesystem,
                        log: config.log,
                        properties: config.systemd,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(ValidatedConfigMap(map))
    }
}

/// Check a profile's `network` table parses, so a typo is reported when the
/// config is read rather than when a command is about to run.
///
/// `"..."` sentinels are skipped: they are resolved later, when profiles merge.
fn validate_network(name: &str, table: &toml::Table) -> Result<()> {
    let config: NetworkConfig = toml::Value::Table(table.clone())
        .try_into()
        .with_context(|| format!("profile '{name}': invalid network policy"))?;
    config
        .validate()
        .with_context(|| format!("profile '{name}': invalid network policy"))
}

/// Convert the raw `match` field into a vec of compiled patterns.
///
/// - `None` (field absent) → `[]` (never matches)
/// - `Some([…])` → compiled entries
fn build_patterns(name: &str, decl: Option<Vec<MatchEntry>>) -> Result<Vec<CommandPattern>> {
    decl.unwrap_or_default()
        .into_iter()
        .map(|e| compile_entry(name, e))
        .collect()
}

fn compile_entry(name: &str, e: MatchEntry) -> Result<CommandPattern> {
    let (pattern, match_type, target) = match e {
        MatchEntry::Simple(s) if s == "..." => return Ok(CommandPattern::Sentinel),
        MatchEntry::Simple(s) => {
            return Ok(CommandPattern::Exact(s, MatchTarget::Command));
        }
        MatchEntry::Extended {
            pattern,
            match_type,
            target,
        } => (pattern, match_type, target),
    };
    // The table form has no implicit pattern: there is nothing sensible to fall
    // back to now that the section name no longer doubles as one.
    let p = pattern.with_context(|| format!("profile '{name}': match entry requires a pattern"))?;
    match match_type {
        MatchType::Exact => Ok(CommandPattern::Exact(p, target)),
        MatchType::Glob => Pattern::new(&p)
            .with_context(|| format!("profile '{name}': invalid glob pattern '{p}'"))
            .map(|pat| CommandPattern::Glob(pat, target)),
        MatchType::Regex => Regex::new(&p)
            .with_context(|| format!("profile '{name}': invalid regex '{p}'"))
            .map(|r| CommandPattern::Regex(r, target)),
    }
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
/// merged (via `extend` or multiple matches) we can no longer tell which file a
/// given property came from.
fn substitute_profile_config_dir(profile: &mut ProfileConfig, dir: &str) {
    for value in profile.systemd.values_mut() {
        substitute_config_dir(value, dir);
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
    let profiles = toml::Value::Table(table)
        .try_into::<ConfigMap>()
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok((profiles, settings))
}

/// Load and merge configs from all search paths (lowest to highest priority).
pub fn load_configs() -> Result<Loaded> {
    let mut merged: ConfigMap = HashMap::new();
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
        let (file_configs, mut file_settings) = split_settings(table, &path)?;

        // Directory containing this config file — the value of `$SCUDO_CONFIG_DIR`
        // for every profile defined in it.
        let config_dir = path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        substitute_settings_config_dir(&mut file_settings, &config_dir);
        settings = file_settings.over(settings);

        let mut synthetic_counter: HashMap<String, usize> = HashMap::new();
        for (name, mut new_profile) in file_configs {
            substitute_profile_config_dir(&mut new_profile, &config_dir);
            // Check for self-reference in extend list.
            let self_pos = new_profile.extend.iter().position(|e| e == &name);
            if let Some(pos) = self_pos {
                // Inherit from the lower-priority same-named profile, unless it is `final`.
                let inheritable = merged.get(&name).is_some_and(|e| !e.r#final);
                if inheritable {
                    let mut existing = merged.remove(&name).expect("just checked");
                    let n = synthetic_counter.entry(name.clone()).or_insert(0);
                    let synthetic = format!("\x00{name}\x00{n}");
                    *n = n.saturating_add(1);
                    existing.r#match = Some(vec![]); // drop its patterns: only the new profile matches
                    merged.insert(synthetic.clone(), existing);
                    if let Some(slot) = new_profile.extend.get_mut(pos) {
                        *slot = synthetic;
                    }
                } else {
                    new_profile.extend.remove(pos); // final or absent — drop self-ref silently
                }
            }
            merged.insert(name, new_profile);
        }
    }
    Ok(Loaded {
        profiles: merged.try_into()?,
        settings,
    })
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

    /// Simulate loading two config layers (lower-priority first, then higher-priority)
    /// and return the resulting `ValidatedConfigMap`.
    fn merge_layers(lower: ConfigMap, higher: ConfigMap) -> Result<ValidatedConfigMap> {
        let mut merged: ConfigMap = HashMap::new();
        let mut synthetic_counter: HashMap<String, usize> = HashMap::new();
        for layer in [lower, higher] {
            for (name, mut new_profile) in layer {
                let self_pos = new_profile.extend.iter().position(|e| e == &name);
                if let Some(pos) = self_pos {
                    let inheritable = merged.get(&name).is_some_and(|e| !e.r#final);
                    if inheritable {
                        let mut existing = merged.remove(&name).expect("just checked");
                        let n = synthetic_counter.entry(name.clone()).or_insert(0);
                        let synthetic = format!("\x00{name}\x00{n}");
                        *n = n.saturating_add(1);
                        existing.r#match = Some(vec![]);
                        merged.insert(synthetic.clone(), existing);
                        if let Some(slot) = new_profile.extend.get_mut(pos) {
                            *slot = synthetic;
                        }
                    } else {
                        new_profile.extend.remove(pos);
                    }
                }
                merged.insert(name, new_profile);
            }
        }
        merged.try_into()
    }

    /// A profile named `app` that also matches the `app` command, so that the
    /// tests below can reach it through `resolve` and not just by name.
    fn simple_profile(cpu: &str) -> ProfileConfig {
        let mut props = HashMap::new();
        props.insert("CPUQuota".to_owned(), toml::Value::String(cpu.to_owned()));
        ProfileConfig {
            r#match: Some(vec![MatchEntry::Simple("app".to_owned())]),
            systemd: props,
            ..Default::default()
        }
    }

    fn patterns_of(src: &str, profile: &str) -> Result<Vec<CommandPattern>> {
        let raw: ConfigMap = toml::from_str(src)?;
        let config = raw.get(profile).context("profile present")?.clone();
        build_patterns(profile, config.r#match)
    }

    #[test]
    fn absent_match_never_matches() {
        // The section name is an identifier, not a pattern: without `match` the
        // profile is reachable only through `extend` or `--profile`.
        let patterns = patterns_of("[curl]\nsystemd.MemoryMax = \"256M\"\n", "curl").unwrap();
        assert!(patterns.is_empty());
    }

    /// Systemd properties belong in the `systemd` sub-table, so a stray key at
    /// the top level is a typo (or the pre-`systemd` layout) rather than a
    /// property — and saying so beats silently dropping it.
    #[test]
    fn unknown_profile_key_is_rejected() {
        let err = toml::from_str::<ConfigMap>("[curl]\nMemoryMax = \"256M\"\n")
            .expect_err("unknown key at the profile level");
        assert!(err.to_string().contains("unknown field `MemoryMax`"));
    }

    #[test]
    fn match_entry_without_pattern_is_rejected() {
        // No implicit fallback to the section name in the table form either.
        for src in [
            "[curl]\nmatch = { type = \"exact\" }\n",
            "[curl]\nmatch = { target = \"full_command\" }\n",
            "[curl]\nmatch = { type = \"glob\" }\n",
            "[curl]\nmatch = { type = \"regex\" }\n",
        ] {
            let err = patterns_of(src, "curl").expect_err("pattern is required");
            assert!(
                format!("{err:#}").contains("requires a pattern"),
                "unexpected error for {src:?}: {err:#}"
            );
        }
    }

    #[test]
    fn invalid_pattern_is_reported() {
        let err = patterns_of(
            "[curl]\nmatch = { pattern = \"[\", type = \"regex\" }\n",
            "curl",
        )
        .expect_err("invalid regex");
        assert!(format!("{err:#}").contains("invalid regex"));
    }

    #[test]
    fn final_allows_replace() {
        // A `final` lower-priority profile can still be replaced outright.
        let mut lower = simple_profile("10%");
        lower.r#final = true;
        let higher = simple_profile("50%");

        let configs = merge_layers(
            HashMap::from([("app".to_owned(), lower)]),
            HashMap::from([("app".to_owned(), higher)]),
        )
        .unwrap();

        let p = &configs.0["app"];
        assert_eq!(
            p.properties.get("CPUQuota"),
            Some(&toml::Value::String("50%".to_owned()))
        );
    }

    #[test]
    fn final_blocks_self_extend() {
        // A `final` lower-priority profile is not usable as a base for self-extend.
        // The self-reference is silently dropped; the higher-priority profile still wins.
        let mut lower = simple_profile("10%");
        lower.r#final = true;

        let mut higher = simple_profile("50%");
        higher.extend = vec!["app".to_owned()]; // self-extend

        let configs = merge_layers(
            HashMap::from([("app".to_owned(), lower)]),
            HashMap::from([("app".to_owned(), higher)]),
        )
        .unwrap();

        let p = &configs.0["app"];
        // Self-ref was dropped → extend is empty → only higher's own property
        assert!(p.extend.is_empty());
        assert_eq!(
            p.properties.get("CPUQuota"),
            Some(&toml::Value::String("50%".to_owned()))
        );
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
        let mut props = HashMap::new();
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

    #[test]
    fn self_extend_inherits_lower_priority() {
        // Higher-priority profile self-extends → lower-priority properties are inherited.
        let lower = simple_profile("10%");

        let mut higher_props = HashMap::new();
        higher_props.insert(
            "MemoryMax".to_owned(),
            toml::Value::String("256M".to_owned()),
        );
        let higher = ProfileConfig {
            r#match: Some(vec![MatchEntry::Simple("app".to_owned())]),
            extend: vec!["app".to_owned()],
            systemd: higher_props,
            ..Default::default()
        };

        let configs = merge_layers(
            HashMap::from([("app".to_owned(), lower)]),
            HashMap::from([("app".to_owned(), higher)]),
        )
        .unwrap();

        let p = &configs.0["app"];
        // extend should now reference the synthetic key (not "app")
        assert!(!p.extend.is_empty());
        assert_ne!(p.extend.first().map(String::as_str), Some("app"));

        // When resolved, both properties should appear
        let r = crate::profile::resolve(&configs, "app", &[]).unwrap();
        let has = |kv: &str| {
            r.systemd_args.windows(2).any(|w| {
                assert_eq!(w.len(), 2);
                w[0] == "-p" && w[1] == kv
            })
        };
        assert!(has("CPUQuota=10%"), "inherited from lower");
        assert!(has("MemoryMax=256M"), "from higher");
    }
}

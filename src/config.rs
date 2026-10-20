use std::{env::VarError, path::PathBuf, sync::OnceLock};

use anyhow::{Context as _, Result, bail};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Deserializer, de};

use crate::{
    logging::LogConfig,
    policy::{DbusConfig, FilesystemConfig, NetworkConfig},
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

/// What a profile's `delegate` says: every delegable profile, some by name, or
/// both, once profiles are combined.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delegate {
    /// `delegate = true`: every profile that is `delegable` and has a `match`.
    pub all: bool,
    /// Profiles named one by one.
    pub names: Vec<String>,
}

impl Delegate {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.all && self.names.is_empty()
    }

    /// Both say what they say: `true` on either side stays, and the names
    /// accumulate like any other list.
    fn merge(&mut self, other: &Delegate) {
        self.all = self.all || other.all;
        union(&mut self.names, &other.names);
    }
}

/// `delegate` as written: `true`, a name, or a list of names. `false` says
/// nothing, since what a profile inherits can only be added to.
fn delegate_spec<'de, D>(de: D) -> Result<Delegate, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Spec {
        All(bool),
        One(String),
        Many(Vec<String>),
    }
    match Spec::deserialize(de).map_err(|_ignored| {
        de::Error::custom("expected true, a profile name or an array of profile names")
    })? {
        Spec::All(all) => Ok(Delegate {
            all,
            names: Vec::new(),
        }),
        Spec::One(name) => Ok(Delegate {
            all: false,
            names: vec![name],
        }),
        Spec::Many(names) => Ok(Delegate { all: false, names }),
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
/// Whether `name` follows the environment variable rules.
pub fn is_var_name(name: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new("^[A-Za-z_][A-Za-z0-9_]*$").expect("regex is valid"))
        .is_match(name)
}

fn validate_vars(vars: &VarDecls) -> Result<()> {
    for (name, decl) in vars {
        if !is_var_name(name) || name.starts_with("arg_") || name == CONFIG_DIR_VAR {
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
    /// Patterns on the command, see [`CommandPattern`]; any one of them
    /// matching is enough. Empty: the profile is reachable only through
    /// `extend` or `--profile`.
    #[serde(rename = "match", default, deserialize_with = "one_or_many")]
    pub r#match: Vec<String>,
    /// Profiles applied before this one.
    #[serde(default, deserialize_with = "one_or_many")]
    pub extend: Vec<String>,
    /// Profiles whose commands, started from inside this sandbox, are run in a
    /// sandbox of their own by a broker outside it: `true` for every profile
    /// that is `delegable`, or their names. Each must have a `match` and be
    /// `delegable`.
    #[serde(default, deserialize_with = "delegate_spec")]
    pub delegate: Delegate,
    /// Whether this profile may be delegated to: run on the request of a
    /// sandbox that lists it, or says `delegate = true`. Inherited through
    /// `extend`. Meant for profiles built to run hostile code confined, never
    /// for ones that grant much.
    pub delegable: Option<bool>,
    /// Whether this profile adds to a same-named one from a lower-priority
    /// config file (the default) or replaces it.
    pub inherit: Option<bool>,
    /// Fields that replace, rather than add to, what a same-named profile from
    /// a lower-priority config file says.
    #[serde(default)]
    pub replace: Vec<Replace>,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    /// Environment variables copied from scudo's own environment into the
    /// unit, by name. One that is not set is left out.
    #[serde(default, deserialize_with = "one_or_many")]
    pub env: Vec<String>,
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
    /// The `[<profile>.dbus]` sub-table: what the command gets of the session
    /// bus.
    #[serde(default)]
    pub dbus: DbusConfig,
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

/// A field `replace` can name.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Replace {
    Match,
}

pub type ConfigMap = IndexMap<String, ProfileConfig>;

/// One `match` entry.
///
/// `"/re/flags"` is a regular expression, unanchored as in sed, with flags
/// among `imsxU`; anything else is a glob on the whole text. A pattern holding
/// a space is compared with the command line (the name, then the arguments
/// joined by single spaces, see [`command_line`]), any other with the name
/// alone.
#[derive(Debug, Clone)]
pub struct CommandPattern {
    source: String,
    kind: PatternKind,
    whole_line: bool,
}

#[derive(Debug, Clone)]
enum PatternKind {
    Glob(glob::Pattern),
    Regex(Regex),
}

impl CommandPattern {
    /// # Errors
    ///
    /// An invalid glob or regex, or an unknown regex flag.
    pub fn new(source: &str) -> Result<Self> {
        let regex = source
            .strip_prefix('/')
            .and_then(|rest| rest.rsplit_once('/'));
        let kind = match regex {
            Some((body, flags)) => {
                if let Some(flag) = flags.chars().find(|c| !"imsxU".contains(*c)) {
                    bail!("unknown regex flag '{flag}'");
                }
                let re = if flags.is_empty() {
                    body.to_owned()
                } else {
                    format!("(?{flags}){body}")
                };
                PatternKind::Regex(Regex::new(&re)?)
            }
            None => PatternKind::Glob(glob::Pattern::new(source)?),
        };
        Ok(CommandPattern {
            source: source.to_owned(),
            kind,
            whole_line: source.contains(' '),
        })
    }

    /// Whether the command `name`, run as `line`, is matched.
    #[must_use]
    pub fn matches(&self, name: &str, line: &str) -> bool {
        let text = if self.whole_line { line } else { name };
        match &self.kind {
            PatternKind::Glob(glob) => glob.matches(text),
            PatternKind::Regex(re) => re.is_match(text),
        }
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl PartialEq for CommandPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

/// What a pattern on the command line is compared with: the command's name and
/// its arguments, joined by single spaces.
#[must_use]
pub fn command_line(name: &str, args: &[String]) -> String {
    core::iter::once(name)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

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
    pub patterns: Vec<CommandPattern>,
    pub extend: Vec<String>,
    pub delegate: Delegate,
    pub delegable: Option<bool>,
    pub exec: Option<String>,
    pub verbose: Option<bool>,
    pub confirm: Option<bool>,
    pub env: Vec<String>,
    pub args: ArgDecls,
    pub vars: VarDecls,
    pub network: Option<toml::Table>,
    pub filesystem: FilesystemConfig,
    pub dbus: DbusConfig,
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
        self.delegate.merge(&other.delegate);
        self.delegable = other.delegable.or(self.delegable);
        self.exec = other.exec.clone().or(self.exec.take());
        self.verbose = other.verbose.or(self.verbose);
        self.confirm = other.confirm.or(self.confirm);
        union(&mut self.env, &other.env);
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
        self.dbus = other.dbus.clone().over(core::mem::take(&mut self.dbus));
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
            .chain(&config.delegate.names)
            .chain(&config.filesystem.write)
            .chain(&config.filesystem.read)
            .chain(&config.filesystem.hide)
            .chain(&config.filesystem.deny)
            .chain(&config.dbus.see)
            .chain(&config.dbus.talk)
            .chain(&config.dbus.own)
            .chain(&config.dbus.call)
            .chain(&config.dbus.broadcast);
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
        config
            .dbus
            .validate()
            .with_context(|| format!("profile '{name}'"))?;
        validate_vars(&config.vars).with_context(|| format!("profile '{name}'"))?;
        if let Some(var) = config.env.iter().find(|var| !is_var_name(var)) {
            bail!("profile '{name}': env: '{var}' is not a valid variable name");
        }
        let patterns = config
            .r#match
            .iter()
            .map(|p| {
                CommandPattern::new(p)
                    .with_context(|| format!("profile '{name}': invalid match pattern '{p}'"))
            })
            .collect::<Result<_>>()?;
        Ok(Profile {
            patterns,
            extend: config.extend,
            delegate: config.delegate,
            delegable: config.delegable,
            exec: config.exec,
            verbose: config.verbose,
            confirm: config.confirm,
            env: config.env,
            args: config.args,
            vars: config.vars,
            network: config.network,
            filesystem: config.filesystem,
            dbus: config.dbus,
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
            let replace_match = config.replace.contains(&Replace::Match);
            let profile = Profile::validate(&name, config)?;
            match self.0.get_mut(&name) {
                Some(existing) if inherit => {
                    if replace_match {
                        existing.patterns.clear();
                    }
                    existing.merge(&profile);
                }
                _ => {
                    self.0.insert(name, profile);
                }
            }
        }
        Ok(())
    }

    /// Check what can only be checked once every file is in: a profile named
    /// in `delegate` has to exist, match something and be `delegable`.
    ///
    /// The broker decides by matching the command's name, so a profile without
    /// `match` could never be reached through it; and a misspelt name would
    /// leave the tool running in the caller's sandbox, which is exactly what
    /// delegating it was meant to prevent. A profile that is not `delegable`
    /// was not written to be run on anyone's request. All three are errors
    /// rather than entries quietly ignored.
    fn check_delegates(&self) -> Result<()> {
        for (name, profile) in &self.0 {
            for delegated in &profile.delegate.names {
                let target = self.0.get(delegated).with_context(|| {
                    format!("profile '{name}': delegated profile '{delegated}' not found")
                })?;
                if target.patterns.is_empty() {
                    bail!(
                        "profile '{name}': delegated profile '{delegated}' has no `match`, \
                         so no command could ever be delegated to it"
                    );
                }
                if !self.is_delegable(delegated) {
                    bail!(
                        "profile '{name}': profile '{delegated}' is not delegable; \
                         set `delegable = true` on it, or on a profile it extends"
                    );
                }
            }
        }
        Ok(())
    }

    /// Whether `name` may be delegated to: its own `delegable`, or else the one
    /// it inherits, the last base to say anything winning as in a merge.
    #[must_use]
    pub fn is_delegable(&self, name: &str) -> bool {
        self.delegable_along(name, &mut Vec::new()).unwrap_or(false)
    }

    /// Whether `name` says, itself or through what it inherits,
    /// `delegable = false`: a delegated run that it matches is refused, even
    /// when another profile matching the same command is delegable.
    #[must_use]
    pub fn refuses_delegation(&self, name: &str) -> bool {
        self.delegable_along(name, &mut Vec::new()) == Some(false)
    }

    fn delegable_along<'a>(&'a self, name: &'a str, path: &mut Vec<&'a str>) -> Option<bool> {
        if path.contains(&name) {
            return None;
        }
        let profile = self.0.get(name)?;
        if profile.delegable.is_some() {
            return profile.delegable;
        }
        path.push(name);
        let inherited = profile
            .extend
            .iter()
            .rev()
            .find_map(|parent| self.delegable_along(parent, path));
        path.pop();
        inherited
    }

    /// The profiles `delegate` stands for, in the order they were defined.
    #[must_use]
    pub fn delegates(&self, delegate: &Delegate) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        if delegate.all {
            names.extend(
                self.0
                    .iter()
                    .filter(|(name, profile)| {
                        !profile.patterns.is_empty() && self.is_delegable(name)
                    })
                    .map(|(name, _)| name.clone()),
            );
        }
        union(&mut names, &delegate.names);
        names
    }

    /// The `match` patterns of each delegated profile, as written.
    #[must_use]
    pub fn delegate_patterns(&self, names: &[String]) -> Vec<(String, Vec<String>)> {
        names
            .iter()
            .filter_map(|name| {
                self.0.get(name).map(|profile| {
                    (
                        name.clone(),
                        profile
                            .patterns
                            .iter()
                            .map(|p| p.as_str().to_owned())
                            .collect(),
                    )
                })
            })
            .collect()
    }
}

impl TryFrom<ConfigMap> for ValidatedConfigMap {
    type Error = anyhow::Error;

    fn try_from(value: ConfigMap) -> Result<Self> {
        let mut map = ValidatedConfigMap::default();
        map.layer(value)?;
        map.check_delegates()?;
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
    load_configs_with(true)
}

/// Like [`load_configs`], but with `interactive` false a project config that is
/// not trusted yet is an error rather than a question.
///
/// A delegated run's standard input belongs to whoever asked for it — an agent,
/// typically — and a `[y/N]` it could answer would let it trust its own config.
pub fn load_configs_with(interactive: bool) -> Result<Loaded> {
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
            trust::check_and_confirm(&canonical, &content, interactive)?;
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
    profiles.check_delegates()?;
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

    /// The configuration shipped as a starting point has to be one scudo accepts,
    /// `delegate = true` included, or the first thing a new user copies is an error.
    #[test]
    fn the_example_config_loads() {
        let (profiles, _) =
            split(include_str!("../examples/config.toml")).expect("the example parses");
        let map = ValidatedConfigMap::try_from(profiles).expect("the example validates");
        assert!(map.is_delegable("npm"));
        assert!(!map.is_delegable("agents"));
        assert!(map.refuses_delegation("cargo-install"));
        assert!(map.refuses_delegation("npm-auth"));
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
        assert!(
            map.0["b"]
                .patterns
                .iter()
                .any(|p| p.matches("code-oss", "code-oss"))
        );
    }

    #[test]
    fn a_pattern_says_what_it_is_and_what_it_matches() {
        let line =
            |p: &str, name: &str, line: &str| CommandPattern::new(p).unwrap().matches(name, line);
        // A glob without a space: the name alone, whole.
        assert!(line("git", "git", "git push"));
        assert!(!line("git", "gitk", "gitk"));
        // With a space: the command line.
        assert!(line("git push*", "git", "git push origin"));
        assert!(!line("git push*", "git", "git status"));
        // A regex, unanchored, on the name unless it holds a space.
        assert!(line("/it/", "git", "nothing"));
        assert!(!line("/^it/", "git", "it"));
        assert!(line("/^git push /", "git", "git push origin"));
        // Flags as in sed.
        assert!(line("/^GIT$/i", "git", ""));
        assert!(!line("/^GIT$/", "git", ""));
        // The last slash closes it.
        assert!(line(r"/a\/b/", "a/b", ""));
    }

    #[test]
    fn an_unknown_regex_flag_is_an_error() {
        let err = profile_error("[a]\nmatch = \"/usr/bin\"\n");
        assert!(err.contains("unknown regex flag 'b'"), "{err}");
        assert!(profile_error("[a]\nmatch = \"/(/\"\n").contains("invalid match pattern"));
    }

    #[test]
    fn the_command_line_is_the_name_and_the_arguments() {
        assert_eq!(command_line("git", &[]), "git");
        assert_eq!(
            command_line("git", &["commit".to_owned(), "-m a b".to_owned()]),
            "git commit -m a b"
        );
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

    /// `replace = ["match"]` takes the patterns from this file alone, and
    /// still adds to everything else.
    #[test]
    fn replace_match_drops_the_inherited_patterns() {
        let map = load(&[
            "[cargo]\nmatch = [\"cargo\", \"rustc\"]\nfilesystem.read = [\"/a\"]\n",
            "[cargo]\nreplace = [\"match\"]\nmatch = \"cargo\"\nfilesystem.read = [\"/b\"]\n",
        ]);
        let cargo = &map.0["cargo"];
        let patterns: Vec<&str> = cargo.patterns.iter().map(CommandPattern::as_str).collect();
        assert_eq!(patterns, ["cargo"]);
        assert_eq!(cargo.filesystem.read, ["/a", "/b"]);

        let map = load(&["[a]\nmatch = \"a\"\n", "[a]\nreplace = [\"match\"]\n"]);
        assert!(map.0["a"].patterns.is_empty(), "nothing left to match");
    }

    #[test]
    fn replace_names_known_fields_only() {
        split("[a]\nreplace = [\"filesystem\"]\n").expect_err("not replaceable");
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
    fn env_names_follow_the_variable_rules() {
        let map = load(&["[a]\nenv = \"TOKEN\"\n"]);
        assert_eq!(map.0["a"].env, ["TOKEN"]);
        for decl in ["env = [\"1X\"]", "env = [\"A=1\"]", "env = [\"\"]"] {
            let (profiles, _) = split(&format!("[a]\n{decl}\n")).unwrap();
            ValidatedConfigMap::try_from(profiles).expect_err(decl);
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

    #[test]
    fn a_delegated_profile_has_to_exist() {
        let raw: ConfigMap = toml::from_str("[agent]\ndelegate = \"npm\"\n").unwrap();
        let err = ValidatedConfigMap::try_from(raw).unwrap_err();
        assert!(format!("{err:#}").contains("'npm' not found"), "{err:#}");
    }

    /// The broker decides by the command's name, so a profile it could never
    /// pick is a mistake to point out, not an entry to skip.
    #[test]
    fn a_delegated_profile_has_to_match_something() {
        let raw: ConfigMap = toml::from_str(
            "[agent]\ndelegate = [\"base\"]\n\n[base]\ndelegable = true\nfilesystem.read = [\"/\"]\n",
        )
        .unwrap();
        let err = ValidatedConfigMap::try_from(raw).unwrap_err();
        assert!(format!("{err:#}").contains("has no `match`"), "{err:#}");
    }

    /// Naming a profile is not enough: it has to have been written to be run
    /// on someone else's request.
    #[test]
    fn a_profile_has_to_be_delegable_to_be_named() {
        let raw: ConfigMap =
            toml::from_str("[agent]\ndelegate = \"code\"\n\n[code]\nmatch = \"code\"\n").unwrap();
        let err = ValidatedConfigMap::try_from(raw).unwrap_err();
        assert!(format!("{err:#}").contains("not delegable"), "{err:#}");
    }

    #[test]
    fn delegable_is_inherited_and_can_be_taken_back() {
        let map = load(&["[base]\ndelegable = true\n\
             [npm]\nextend = \"base\"\nmatch = \"npm\"\n\
             [risky]\nextend = \"base\"\nmatch = \"risky\"\ndelegable = false\n\
             [code]\nmatch = \"code\"\n"]);
        assert!(map.is_delegable("npm"));
        assert!(!map.is_delegable("risky"));
        assert!(!map.is_delegable("code"));
        assert!(map.refuses_delegation("risky"));
        assert!(
            !map.refuses_delegation("code"),
            "saying nothing refuses nothing"
        );
        assert!(!map.refuses_delegation("npm"));
    }

    /// `true` stands for every delegable profile a command could match, and
    /// nothing else: not a base without `match`, not one never marked.
    #[test]
    fn delegating_everything_means_every_delegable_profile() {
        let map = load(&["[base]\ndelegable = true\n\
             [npm]\nextend = \"base\"\nmatch = \"npm\"\n\
             [cargo]\nmatch = \"cargo\"\ndelegable = true\n\
             [code]\nmatch = \"code\"\n\
             [agent]\ndelegate = true\n"]);
        let agent = map.0.get("agent").unwrap();
        assert_eq!(map.delegates(&agent.delegate), ["npm", "cargo"]);
        assert_eq!(
            map.delegate_patterns(&map.delegates(&agent.delegate)),
            [
                ("npm".to_owned(), vec!["npm".to_owned()]),
                ("cargo".to_owned(), vec!["cargo".to_owned()]),
            ]
        );
    }

    #[test]
    fn delegates_accumulate_through_extend_and_layers() {
        let map = load(&[
            "[base]\ndelegate = \"npm\"\n[npm]\nmatch = \"npm\"\ndelegable = true\n\
             [cargo]\nmatch = \"cargo\"\ndelegable = true\n",
            "[base]\ndelegate = [\"cargo\", \"npm\"]\n",
        ]);
        let base = map.0.get("base").unwrap();
        assert_eq!(base.delegate.names, ["npm", "cargo"]);
        assert!(!base.delegate.all);
        let map = load(&[
            "[base]\ndelegate = \"npm\"\n[npm]\nmatch = \"npm\"\n",
            "[base]\ndelegate = true\n",
        ]);
        assert!(map.0.get("base").unwrap().delegate.all);
    }
}

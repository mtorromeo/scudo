use std::{collections::HashMap, env::VarError, path::PathBuf};

use anyhow::{Context as _, Result};
use glob::Pattern;
use regex::Regex;
use serde::Deserialize;

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

use crate::trust;

#[derive(Debug, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    #[default]
    Glob,
    Exact,
    Regex,
    Never,
}

#[derive(Debug, Clone)]
pub enum CommandPattern {
    Exact(String),
    Regex(Regex),
    Glob(Pattern),
    Never,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProfileConfig {
    pub pattern: Option<String>,
    #[serde(rename = "match", default = "default_match_type")]
    pub r#match: MatchType,
    pub extend: Option<String>,
    pub exec: Option<String>,
    pub debug: Option<bool>,
    pub confirm: Option<bool>,
    /// Maps variable names to the flag(s) that populate them.
    #[serde(default)]
    pub arg_aliases: ArgAliases,
    /// Flags that take no value (boolean flags); prevents consuming the next arg.
    #[serde(default)]
    pub arg_flags: Vec<String>,
    /// All systemd unit properties, keyed by their exact systemd name.
    /// Values are either a single string/bool/integer or an array thereof.
    #[serde(flatten)]
    pub properties: HashMap<String, toml::Value>,
}

fn default_match_type() -> MatchType {
    MatchType::Exact
}

pub type ConfigMap = HashMap<String, ProfileConfig>;

#[derive(Debug, Clone)]
pub struct ValidatedProfileConfig {
    pub pattern: CommandPattern,
    pub extend: Option<String>,
    pub exec: Option<String>,
    pub debug: Option<bool>,
    pub confirm: Option<bool>,
    pub arg_aliases: ArgAliases,
    pub arg_flags: Vec<String>,
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
                let pattern = parse_pattern(&name, config.pattern, &config.r#match)?;
                Ok((
                    name,
                    ValidatedProfileConfig {
                        pattern,
                        extend: config.extend,
                        exec: config.exec,
                        debug: config.debug,
                        confirm: config.confirm,
                        arg_aliases: config.arg_aliases,
                        arg_flags: config.arg_flags,
                        properties: config.properties,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(ValidatedConfigMap(map))
    }
}

fn parse_pattern(
    name: &str,
    pattern: Option<String>,
    match_type: &MatchType,
) -> Result<CommandPattern> {
    if matches!(match_type, MatchType::Never) {
        return Ok(CommandPattern::Never);
    }
    let p = pattern.unwrap_or_else(|| name.to_owned());
    match match_type {
        MatchType::Exact => Ok(CommandPattern::Exact(p)),
        MatchType::Glob => Pattern::new(&p)
            .with_context(|| format!("profile '{name}': invalid glob pattern '{p}'"))
            .map(CommandPattern::Glob),
        MatchType::Regex => Regex::new(&p)
            .with_context(|| format!("profile '{name}': invalid regex '{p}'"))
            .map(CommandPattern::Regex),
        MatchType::Never => Ok(CommandPattern::Never),
    }
}

/// Load and merge configs from all search paths (lowest to highest priority).
pub fn load_configs() -> Result<ValidatedConfigMap> {
    let mut merged: ConfigMap = HashMap::new();
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

        let file_configs: ConfigMap =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        merged.extend(file_configs);
    }
    merged.try_into()
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

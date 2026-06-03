use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use glob::Pattern;
use regex::Regex;
use serde::Deserialize;

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
    /// All systemd unit properties, keyed by their exact systemd name (PascalCase).
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
                let pattern = parse_pattern(&name, config.pattern, config.r#match)?;
                Ok((
                    name,
                    ValidatedProfileConfig {
                        pattern,
                        extend: config.extend,
                        exec: config.exec,
                        debug: config.debug,
                        confirm: config.confirm,
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
    match_type: MatchType,
) -> Result<CommandPattern> {
    let Some(p) = pattern else {
        return Ok(CommandPattern::Never);
    };
    match match_type {
        MatchType::Glob => Pattern::new(&p)
            .with_context(|| format!("profile '{name}': invalid glob pattern '{p}'"))
            .map(CommandPattern::Glob),
        MatchType::Exact => Ok(CommandPattern::Exact(p)),
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
        let file_configs: ConfigMap =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        merged.extend(file_configs);
    }
    merged.try_into()
}

fn config_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    paths.push(PathBuf::from("/etc/scudo/config.toml"));

    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| match std::env::var("HOME") {
            Ok(home) => Ok(PathBuf::from(home).join(".config")),
            Err(err) => Err(err),
        })
    {
        paths.push(xdg_config.join("scudo/config.toml"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join(".scudo.toml"));
    }

    paths
}

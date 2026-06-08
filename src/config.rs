use std::{collections::HashMap, env::VarError, path::PathBuf};

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
    pub extend: Vec<String>,
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

        let mut synthetic_counter: HashMap<String, usize> = HashMap::new();
        for (name, mut new_profile) in file_configs {
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
                    existing.r#match = MatchType::Never; // prevent direct command matching
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

#[cfg(test)]
mod tests {
    use super::*;

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
                        existing.r#match = MatchType::Never;
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

    fn simple_profile(cpu: &str) -> ProfileConfig {
        let mut props = HashMap::new();
        props.insert("CPUQuota".to_owned(), toml::Value::String(cpu.to_owned()));
        ProfileConfig {
            properties: props,
            ..Default::default()
        }
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

        let p = configs.0.get("app").unwrap();
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

        let p = configs.0.get("app").unwrap();
        // Self-ref was dropped → extend is empty → only higher's own property
        assert!(p.extend.is_empty());
        assert_eq!(
            p.properties.get("CPUQuota"),
            Some(&toml::Value::String("50%".to_owned()))
        );
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
            extend: vec!["app".to_owned()],
            properties: higher_props,
            ..Default::default()
        };

        let configs = merge_layers(
            HashMap::from([("app".to_owned(), lower)]),
            HashMap::from([("app".to_owned(), higher)]),
        )
        .unwrap();

        let p = configs.0.get("app").unwrap();
        // extend should now reference the synthetic key (not "app")
        assert!(!p.extend.is_empty());
        assert_ne!(p.extend.first().map(String::as_str), Some("app"));

        // When resolved, both properties should appear
        let r = crate::profile::resolve(&configs, "app", &[]).unwrap();
        let has = |kv: &str| {
            r.systemd_args
                .windows(2)
                .any(|w| w[0] == "-p" && w[1] == kv)
        };
        assert!(has("CPUQuota=10%"), "inherited from lower");
        assert!(has("MemoryMax=256M"), "from higher");
    }
}

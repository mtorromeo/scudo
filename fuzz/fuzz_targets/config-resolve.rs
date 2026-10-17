//! Validating a config and resolving a command against it. A project's
//! `.scudo.toml` is written by whoever wrote the project, and is only shown to
//! the user — it is parsed in full before anyone has said yes.
//!
//! This starts from the profile map, so `[scudo]` is just another profile name
//! here: the split that takes it out is private to `config.rs`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scudo::{
    config::{ConfigMap, ValidatedConfigMap},
    profile::{self, ResolveOptions},
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    // The command line first, then a NUL, then the config.
    let (command_line, config) = text.split_once('\0').unwrap_or(("curl", text));
    let mut words = command_line.split_whitespace().map(str::to_owned);
    let command = words.next().unwrap_or_default();
    let args: Vec<String> = words.collect();

    let Ok(raw) = toml::from_str::<ConfigMap>(config) else {
        return;
    };
    let Ok(configs) = ValidatedConfigMap::try_from(raw) else {
        return;
    };

    drop(profile::resolve(&configs, &command, &args));

    // Every profile, selected by name, reaches the ones no command matches.
    let names: Vec<String> = configs.0.keys().cloned().collect();
    drop(profile::resolve_with(
        &configs,
        &command,
        &args,
        ResolveOptions {
            profiles: &names,
            no_match: true,
            ..ResolveOptions::default()
        },
    ));
});

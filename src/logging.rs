//! Leveled, structured logging for scudo.
//!
//! Everything scudo says about itself goes through here: the level and the
//! destination are chosen by the user, from the command line or from a profile's
//! `log` table. What stays out is the interactive UI — the trust diff, the
//! confirmation prompt — which is not a log and must not end up in a file or in
//! syslog.
//!
//! The subscriber is installed before anything else runs and swapped later:
//! a profile's `log` settings cannot be read until the config has been read, and
//! reading it is itself something worth reporting. [`init`] puts a stderr
//! subscriber in place immediately, and [`Handle::reconfigure`] replaces the
//! whole destination layer once more is known.

use std::{
    fs::OpenOptions,
    io::{IsTerminal as _, Write as _},
    sync::{Mutex, Once},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Deserializer};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context as LayerContext, SubscriberExt as _},
    reload,
    util::SubscriberInitExt as _,
};

/// How loud scudo is when nothing says otherwise.
///
/// Warnings and errors only — the same set of messages the tool printed before
/// it had levels at all.
pub const DEFAULT_LEVEL: Level = Level::Warn;

/// How much is reported. Ordered from quietest to loudest, so `max` and `>=`
/// mean what they read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Say nothing at all.
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<Level> for LevelFilter {
    fn from(level: Level) -> Self {
        match level {
            Level::Off => LevelFilter::OFF,
            Level::Error => LevelFilter::ERROR,
            Level::Warn => LevelFilter::WARN,
            Level::Info => LevelFilter::INFO,
            Level::Debug => LevelFilter::DEBUG,
            Level::Trace => LevelFilter::TRACE,
        }
    }
}

impl std::str::FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Level::Off),
            "error" => Ok(Level::Error),
            "warn" | "warning" => Ok(Level::Warn),
            "info" => Ok(Level::Info),
            "debug" => Ok(Level::Debug),
            "trace" => Ok(Level::Trace),
            other => anyhow::bail!(
                "invalid log level '{other}' (expected off, error, warn, info, debug or trace)"
            ),
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match *self {
            Level::Off => "off",
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        })
    }
}

/// Where the output goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Stderr,
    File,
    Syslog,
    Journald,
}

impl std::str::FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "stderr" => Ok(Target::Stderr),
            "file" => Ok(Target::File),
            "syslog" => Ok(Target::Syslog),
            "journald" => Ok(Target::Journald),
            other => anyhow::bail!(
                "invalid log target '{other}' (expected stderr, file, syslog or journald)"
            ),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match *self {
            Target::Stderr => "stderr",
            Target::File => "file",
            Target::Syslog => "syslog",
            Target::Journald => "journald",
        })
    }
}

/// The syslog facility messages are filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Facility {
    Auth,
    Authpriv,
    Cron,
    Daemon,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
    User,
}

impl Facility {
    const fn code(self) -> libc::c_int {
        match self {
            Facility::Auth => libc::LOG_AUTH,
            Facility::Authpriv => libc::LOG_AUTHPRIV,
            Facility::Cron => libc::LOG_CRON,
            Facility::Daemon => libc::LOG_DAEMON,
            Facility::Local0 => libc::LOG_LOCAL0,
            Facility::Local1 => libc::LOG_LOCAL1,
            Facility::Local2 => libc::LOG_LOCAL2,
            Facility::Local3 => libc::LOG_LOCAL3,
            Facility::Local4 => libc::LOG_LOCAL4,
            Facility::Local5 => libc::LOG_LOCAL5,
            Facility::Local6 => libc::LOG_LOCAL6,
            Facility::Local7 => libc::LOG_LOCAL7,
            Facility::User => libc::LOG_USER,
        }
    }
}

impl std::fmt::Display for Facility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match *self {
            Facility::Auth => "auth",
            Facility::Authpriv => "authpriv",
            Facility::Cron => "cron",
            Facility::Daemon => "daemon",
            Facility::Local0 => "local0",
            Facility::Local1 => "local1",
            Facility::Local2 => "local2",
            Facility::Local3 => "local3",
            Facility::Local4 => "local4",
            Facility::Local5 => "local5",
            Facility::Local6 => "local6",
            Facility::Local7 => "local7",
            Facility::User => "user",
        })
    }
}

impl std::str::FromStr for Facility {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auth" => Ok(Facility::Auth),
            "authpriv" => Ok(Facility::Authpriv),
            "cron" => Ok(Facility::Cron),
            "daemon" => Ok(Facility::Daemon),
            "local0" => Ok(Facility::Local0),
            "local1" => Ok(Facility::Local1),
            "local2" => Ok(Facility::Local2),
            "local3" => Ok(Facility::Local3),
            "local4" => Ok(Facility::Local4),
            "local5" => Ok(Facility::Local5),
            "local6" => Ok(Facility::Local6),
            "local7" => Ok(Facility::Local7),
            "user" => Ok(Facility::User),
            other => anyhow::bail!("invalid syslog facility '{other}'"),
        }
    }
}

/// The `log` table of a profile, and the same shape the command line fills in.
///
/// Every field is optional so that a higher-priority source can leave the ones
/// it does not mention to a lower one — see [`LogConfig::over`].
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    pub level: Option<Level>,
    /// One target or several; a message goes to all of them.
    #[serde(default, rename = "target", deserialize_with = "deserialize_targets")]
    pub targets: Option<Vec<Target>>,
    /// Kept as a string so `$SCUDO_CONFIG_DIR` can still be substituted into it.
    pub path: Option<String>,
    pub syslog_facility: Option<Facility>,
}

impl LogConfig {
    /// Fields set on `self` win; the rest fall back to `lower`.
    #[must_use]
    pub fn over(self, lower: Self) -> Self {
        LogConfig {
            level: self.level.or(lower.level),
            targets: self.targets.or(lower.targets),
            path: self.path.or(lower.path),
            syslog_facility: self.syslog_facility.or(lower.syslog_facility),
        }
    }

    /// The level in force, once the defaults are filled in.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level.unwrap_or(DEFAULT_LEVEL)
    }

    /// Raise the level to at least `floor`, leaving a louder one alone.
    pub fn raise_to(&mut self, floor: Level) {
        self.level = Some(self.level().max(floor));
    }

    /// `true` when messages go to the terminal.
    ///
    /// Asked by anything that is about to draw on that terminal itself: a log
    /// line written underneath a full-screen UI lands in the middle of it.
    #[must_use]
    pub fn writes_to_stderr(&self) -> bool {
        self.resolved_targets().contains(&Target::Stderr)
    }

    /// The targets in force. Naming a path without naming a target means the
    /// file: there is nothing else the path could have been for.
    fn resolved_targets(&self) -> Vec<Target> {
        self.targets.clone().unwrap_or_else(|| {
            if self.path.is_some() {
                vec![Target::File]
            } else {
                vec![Target::Stderr]
            }
        })
    }
}

/// Accept `target = "file"` as well as `target = ["stderr", "file"]`.
fn deserialize_targets<'de, D>(deserializer: D) -> Result<Option<Vec<Target>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Target),
        Many(Vec<Target>),
    }

    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => None,
        Some(OneOrMany::One(target)) => Some(vec![target]),
        Some(OneOrMany::Many(targets)) => Some(targets),
    })
}

/// The destination stack, boxed so it can be replaced wholesale.
///
/// Layers cannot be added to a subscriber after it is installed, so the part
/// that changes has to be behind one reloadable box rather than one layer per
/// possible target.
type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

/// The subscriber the level filter sits on top of.
type Stacked = tracing_subscriber::layer::Layered<reload::Layer<BoxedLayer, Registry>, Registry>;

/// Lets the destination and the level be swapped once the config has had its say.
pub struct Handle {
    destination: reload::Handle<BoxedLayer, Registry>,
    /// A layer of its own rather than `Layer::with_filter`: a per-layer filter
    /// is handed its identity when the subscriber is built, and a layer reloaded
    /// into place afterwards never gets one — it panics on the first event.
    level: reload::Handle<LevelFilter, Stacked>,
}

impl Handle {
    /// Replace the destination and the level with the ones `config` asks for.
    pub fn reconfigure(&self, config: &LogConfig) -> Result<()> {
        // The destination first: raising the level before there is somewhere for
        // the extra events to go would send them to the old one.
        self.destination
            .reload(build_layer(config)?)
            .context("installing the logging destination")?;
        self.level
            .reload(LevelFilter::from(config.level()))
            .context("installing the logging level")
    }
}

/// Install the subscriber. Call this first: everything before it is unreported.
///
/// The initial destination is stderr at [`DEFAULT_LEVEL`], which is what scudo
/// did before it had a choice, and what it falls back to if the command line or
/// the config turns out to be unusable.
#[must_use]
pub fn init() -> Handle {
    // aya and fuser log through the `log` facade; without this their records go
    // nowhere at all.
    drop(tracing_log::LogTracer::init());

    // Stderr needs nothing opened and nothing reached, so this cannot fail.
    let layer =
        build_layer(&LogConfig::default()).expect("the default configuration always builds");
    let (destination, destination_handle) = reload::Layer::new(layer);
    let (level, level_handle) = reload::Layer::new(LevelFilter::from(DEFAULT_LEVEL));
    drop(Registry::default().with(destination).with(level).try_init());
    Handle {
        destination: destination_handle,
        level: level_handle,
    }
}

fn build_layer(config: &LogConfig) -> Result<BoxedLayer> {
    let mut layers: Vec<BoxedLayer> = Vec::new();

    for target in config.resolved_targets() {
        match target {
            Target::Stderr => layers.push(Box::new(TextLayer::new(StderrSink::new()))),
            Target::File => {
                let path = config
                    .path
                    .as_ref()
                    .context("log target 'file' needs a path: set log.path, or pass --log-file")?;
                layers.push(Box::new(TextLayer::new(FileSink::open(path)?)));
            }
            Target::Syslog => layers.push(Box::new(TextLayer::new(SyslogSink::new(
                config.syslog_facility.unwrap_or(Facility::User),
            )))),
            Target::Journald => {
                let layer = tracing_journald::layer()
                    .context("log target 'journald': cannot reach the journal")?;
                layers.push(Box::new(layer));
            }
        }
    }

    Ok(Box::new(layers))
}

/// One event, flattened into the parts a sink needs.
#[derive(Debug, Default)]
struct Record {
    message: String,
    fields: Vec<(&'static str, String)>,
}

impl Record {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push((field.name(), value));
        }
    }

    /// `key=value, key=value`, or nothing when the event carried no fields.
    ///
    /// Only shown at debug and below: at info and above the message is written
    /// to stand on its own, and repeating its parts after it just adds noise.
    fn rendered_fields(&self) -> String {
        if self.fields.is_empty() {
            return String::new();
        }
        let joined = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" ({joined})")
    }
}

impl Visit for Record {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_owned());
    }
}

/// A destination for formatted text.
trait Sink: Send + Sync + 'static {
    fn emit(&self, meta: &Metadata<'_>, record: &Record);
}

/// Turns events into [`Record`]s and hands them to one sink.
struct TextLayer<S: Sink>(S);

impl<S: Sink> TextLayer<S> {
    const fn new(sink: S) -> Self {
        TextLayer(sink)
    }
}

impl<Sub: Subscriber, S: Sink> Layer<Sub> for TextLayer<S> {
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, Sub>) {
        let mut record = Record::default();
        event.record(&mut record);
        self.0.emit(event.metadata(), &record);
    }
}

/// stderr, in the shape scudo has always used: `scudo: warning: …`.
struct StderrSink {
    /// `systemd-run --pty` leaves the terminal in raw mode, where a bare newline
    /// moves down without returning to column zero and every line after the
    /// first comes out further indented than the last.
    crlf: bool,
}

impl StderrSink {
    fn new() -> Self {
        StderrSink {
            crlf: std::io::stderr().is_terminal(),
        }
    }
}

impl Sink for StderrSink {
    fn emit(&self, meta: &Metadata<'_>, record: &Record) {
        let level = match *meta.level() {
            tracing::Level::ERROR => "error: ",
            tracing::Level::WARN => "warning: ",
            tracing::Level::INFO => "",
            tracing::Level::DEBUG => "debug: ",
            tracing::Level::TRACE => "trace: ",
        };
        // At info and above the message is written to stand on its own, and
        // repeating the parts it was built from would only be noise.
        let fields = if *meta.level() >= tracing::Level::DEBUG {
            record.rendered_fields()
        } else {
            String::new()
        };
        let newline = if self.crlf { "\r\n" } else { "\n" };
        let line = format!("scudo: {level}{}{fields}{newline}", record.message);
        drop(std::io::stderr().write_all(line.as_bytes()));
    }
}

/// A plain text file, appended to. Rotation is logrotate's job.
struct FileSink(Mutex<std::fs::File>);

impl FileSink {
    fn open(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening log file {path}"))?;
        Ok(FileSink(Mutex::new(file)))
    }
}

impl Sink for FileSink {
    fn emit(&self, meta: &Metadata<'_>, record: &Record) {
        let line = format!(
            "{} {:<5} {} {}{}\n",
            timestamp(),
            meta.level(),
            meta.target(),
            record.message,
            record.rendered_fields(),
        );
        if let Ok(mut file) = self.0.lock() {
            drop(file.write_all(line.as_bytes()));
        }
    }
}

/// The system logger, through `syslog(3)`.
struct SyslogSink {
    facility: libc::c_int,
}

/// `openlog` keeps the pointer it is given, so the ident has to outlive every
/// call — a literal does, a `CString` built at run time would not.
static IDENT: &std::ffi::CStr = c"scudo";
static OPEN: Once = Once::new();

impl SyslogSink {
    fn new(facility: Facility) -> Self {
        OPEN.call_once(|| {
            // SAFETY: `IDENT` is a 'static C string, which is what openlog
            // requires of the pointer it retains.
            unsafe {
                libc::openlog(IDENT.as_ptr(), libc::LOG_PID, libc::LOG_USER);
            }
        });
        SyslogSink {
            facility: facility.code(),
        }
    }
}

impl Sink for SyslogSink {
    fn emit(&self, meta: &Metadata<'_>, record: &Record) {
        let priority = match *meta.level() {
            tracing::Level::ERROR => libc::LOG_ERR,
            tracing::Level::WARN => libc::LOG_WARNING,
            tracing::Level::INFO => libc::LOG_INFO,
            tracing::Level::DEBUG | tracing::Level::TRACE => libc::LOG_DEBUG,
        };
        let text = format!("{}{}", record.message, record.rendered_fields());
        // A NUL in the middle would truncate the message; there is nothing to
        // report about a message that cannot be reported, so it is dropped.
        let Ok(message) = std::ffi::CString::new(text) else {
            return;
        };
        // SAFETY: both pointers are to NUL-terminated strings that outlive the
        // call, and the format string consumes exactly the one argument given.
        unsafe {
            libc::syslog(self.facility | priority, c"%s".as_ptr(), message.as_ptr());
        }
    }
}

/// Local time as `2026-09-07T14:03:22+0200`, via libc rather than a date crate.
fn timestamp() -> String {
    // SAFETY: passing null asks for the value to be returned rather than stored.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: `tm` is plain old data with no invalid bit patterns.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to live, correctly typed locals.
    if unsafe { libc::localtime_r(&raw const now, &raw mut tm) }.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 40];
    // SAFETY: the buffer is writable for the length passed, and the format
    // string is a 'static NUL-terminated literal.
    let written = unsafe {
        libc::strftime(
            buf.as_mut_ptr().cast(),
            buf.len(),
            c"%Y-%m-%dT%H:%M:%S%z".as_ptr(),
            &raw const tm,
        )
    };
    String::from_utf8_lossy(buf.get(..written).unwrap_or_default()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> LogConfig {
        toml::from_str(toml).expect("a valid log table")
    }

    #[test]
    fn a_single_target_and_a_list_of_them_read_the_same_way() {
        assert_eq!(
            parse(r#"target = "syslog""#).targets,
            Some(vec![Target::Syslog])
        );
        assert_eq!(
            parse(r#"target = ["stderr", "file"]"#).targets,
            Some(vec![Target::Stderr, Target::File])
        );
    }

    /// The whole point of keeping the table typed: a misspelled key is a config
    /// error, not a setting that silently does nothing.
    #[test]
    fn an_unknown_key_is_rejected() {
        let err = toml::from_str::<LogConfig>(r#"levl = "debug""#).expect_err("should be rejected");
        assert!(err.to_string().contains("levl"), "{err}");
    }

    #[test]
    fn an_unknown_level_is_rejected() {
        toml::from_str::<LogConfig>(r#"level = "loud""#).expect_err("not a level");
    }

    /// Precedence, not loudness: a command must be able to be quieter than the
    /// catch-all profile that set the default, as well as louder.
    #[test]
    fn the_higher_priority_setting_wins_in_both_directions() {
        let base = parse(r#"level = "info""#);
        assert_eq!(
            parse(r#"level = "trace""#).over(base.clone()).level(),
            Level::Trace
        );
        assert_eq!(parse(r#"level = "error""#).over(base).level(), Level::Error);
    }

    #[test]
    fn unset_fields_fall_through_to_the_lower_source() {
        let lower = parse(
            r#"
            level = "debug"
            target = "file"
            path = "/tmp/scudo.log"
        "#,
        );
        let merged = parse(r#"level = "warn""#).over(lower);
        assert_eq!(merged.level(), Level::Warn);
        assert_eq!(merged.targets, Some(vec![Target::File]));
        assert_eq!(merged.path.as_deref(), Some("/tmp/scudo.log"));
    }

    #[test]
    fn nothing_configured_means_warnings_on_stderr() {
        let config = LogConfig::default();
        assert_eq!(config.level(), Level::Warn);
        assert_eq!(config.resolved_targets(), vec![Target::Stderr]);
    }

    /// A path is only ever for the file target, so naming one is enough.
    #[test]
    fn a_path_on_its_own_selects_the_file() {
        assert_eq!(
            parse(r#"path = "/tmp/scudo.log""#).resolved_targets(),
            vec![Target::File]
        );
    }

    #[expect(clippy::panic, reason = "the else arm of a let-else in a test")]
    #[test]
    fn the_file_target_without_a_path_is_an_error() {
        let Err(err) = build_layer(&parse(r#"target = "file""#)) else {
            panic!("a file target with nowhere to write should be rejected");
        };
        assert!(err.to_string().contains("needs a path"), "{err}");
    }

    #[test]
    fn raising_the_level_never_makes_it_quieter() {
        let mut config = parse(r#"level = "trace""#);
        config.raise_to(Level::Debug);
        assert_eq!(config.level(), Level::Trace);

        let mut config = parse(r#"level = "error""#);
        config.raise_to(Level::Debug);
        assert_eq!(config.level(), Level::Debug);
    }

    #[test]
    fn levels_parse_from_the_command_line_too() {
        assert_eq!("WARN".parse::<Level>().expect("valid"), Level::Warn);
        assert_eq!("warning".parse::<Level>().expect("valid"), Level::Warn);
        "loud".parse::<Level>().expect_err("not a level");
        assert_eq!(
            "Journald".parse::<Target>().expect("valid"),
            Target::Journald
        );
        "smoke-signal".parse::<Target>().expect_err("not a target");
    }

    #[test]
    fn a_timestamp_looks_like_one() {
        let now = timestamp();
        assert!(now.len() >= 19, "{now}");
        assert!(now.contains('T'), "{now}");
    }
}

# Logging

Everything scudo says about itself — warnings, the resolution trace, what a sandbox refused —
goes through one leveled logger. Both the level and the destination come from a `log` table on
the profile:

```toml
[curl]
match = "curl"
log.level = "debug"                  # off, error, warn, info, debug, trace
log.target = "file"                  # stderr, file, syslog, journald
log.path = "$SCUDO_CONFIG_DIR/scudo.log"
log.syslog_facility = "user"         # only read by target = "syslog"
```

`log.target` takes one target or a list of them, and a message goes to all of them. Naming a
`log.path` and no target selects the file, since there is nothing else the path could be for.
The default is `warn` on stderr — exactly the set of messages scudo printed before it had
levels at all.

Defaults for every command go in the reserved `[scudo]` section:

```toml
[scudo]
log.level = "info"
log.target = "journald"
```

It sits **under** the profiles rather than over them, which is what makes it a default: a
profile can be quieter than it as well as louder — unlike `verbose`, which only ever adds. A
profile matching everything says the same thing and is still perfectly good:

```toml
[default]
match = "*"
log.level = "info"
```

Between two profiles the ordinary order applies (the one written later wins, and `--profile`
above all; see [Combining profiles](configuration/matching.md#combining-profiles)), so write the catch-all first. `verbose = true` is still accepted and means `log.level = "debug"`; a level
written out next to it wins, being the more specific of the two.

The command line overrides the profiles:

```console
$ scudo --log-level debug -- curl https://example.com/
$ scudo --log-file /tmp/scudo.log -- npm install
$ scudo --log-target syslog,stderr -- rsync -a src/ dst/
```

`-v`/`--verbose` raises the floor to `debug` rather than setting it, so it cannot quieten a
`--log-level trace` written beside it. Each flag also reads an environment variable
(`SCUDO_LOG_LEVEL`, `SCUDO_LOG_TARGET`, `SCUDO_LOG_FILE`, `SCUDO_LOG_SYSLOG_FACILITY`).

Anything scudo emits while it is still reading the config obeys the command line and the
environment, not the config — the setting is not known yet. Use `--log-level` or
`SCUDO_LOG_LEVEL` to see that part of a run.

Stderr keeps the shape it always had (`scudo: warning: …`), with the event's fields appended
only at `debug` and below; a file adds a timestamp and the level; syslog and journald receive
the fields as fields. The confirmation prompt and the trust diff are **not** logs: they are
interactive output and always go to stderr, whatever the destination.

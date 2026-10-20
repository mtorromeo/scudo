# Usage

```
Usage: scudo [OPTIONS] <COMMAND> [COMMAND_ARGS]...

Arguments:
  <COMMAND>          
  [COMMAND_ARGS]...  

Options:
  -v, --verbose                         Enable verbose output. A shorthand for `--log-level debug`
      --log-level <LEVEL>               How much to report: off, error, warn, info, debug or trace [env: SCUDO_LOG_LEVEL]
      --log-target <TARGET>             Where to report it: stderr, file, syslog or journald (repeatable) [env: SCUDO_LOG_TARGET]
      --log-file <PATH>                 Write the log to this file. Implies `--log-target file` [env: SCUDO_LOG_FILE]
      --log-syslog-facility <FACILITY>  The syslog facility to log under. Only used by `--log-target syslog` [env: SCUDO_LOG_SYSLOG_FACILITY]
      --confirm                         Confirm before running the command
  -P, --property <PROPERTY=VALUE>       Set a property for the systemd-run command
  -p, --profile <NAME>                  Apply the named profile, ignoring its match rules (repeatable, comma-separated)
      --no-match                        Skip profile matching; apply only the profiles given with --profile
      --delegate                        Run commands started inside the sandbox under their own profile when it is delegable, as `delegate = true` does
      --no-delegate                     Run every command started inside the sandbox in the sandbox itself, whatever `delegate` says
      --allow-dest <DEST>               Allow a destination (address, CIDR, host or glob), even one a profile denies (repeatable, comma-separated)
      --deny-dest <DEST>                Deny a destination, even one a profile allows (repeatable, comma-separated)
      --allow-port <PORT[/PROTO]>       Allow a port or range, optionally `/tcp` or `/udp`, even one a profile denies (repeatable, comma-separated)
      --deny-port <PORT[/PROTO]>        Deny a port or range, optionally `/tcp` or `/udp`, even one a profile allows (repeatable, comma-separated)
      --fs-hide <PATH>                  Hide a directory behind an empty one, even one a profile grants (repeatable)
      --fs-read <PATH>                  Make a path read-only, even one a profile hides or makes writable (repeatable)
      --fs-write <PATH>                 Make a path writable, even one a profile hides or makes read-only (repeatable)
      --deny-env <PATTERN>              Keep environment variables out of the sandbox, by name or glob, as `deny_env` in a profile does (repeatable, comma-separated)
  -E, --allow-env <PATTERN>             Copy environment variables into the sandbox even when denied, as `allow_env` in a profile does (repeatable, comma-separated)
      --tui                             Run the command in scudo's terminal UI, beside a live list of blocks
      --tui-prefix <KEY>                The UI's prefix key, as `C-a`, `M-x` or `F12`. Overrides `[scudo]`
  -h, --help                            Print help
  -V, --version                         Print version
```

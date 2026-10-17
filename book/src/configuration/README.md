# Configuration

Profiles are loaded from the following paths in order, with later files taking precedence over earlier ones:

| Path | Scope |
|------|-------|
| `/etc/scudo/config.toml` | system-wide |
| `$XDG_CONFIG_HOME/scudo/config.toml` | per-user |
| `/.scudo.toml` … `$PWD/.scudo.toml` | per-directory |

To start from something that already works, copy the
[recommended configuration](recommended.md#recommended-configuration) to
`$XDG_CONFIG_HOME/scudo/config.toml` and adapt it.

For the per-directory tier, scudo walks every ancestor of `$PWD` from the filesystem root down to the current directory, loading each `.scudo.toml` it finds. This lets a project directory override settings defined higher up the tree. For example, with `$PWD` set to `/home/user/projects/myapp`, the lookup order is `/.scudo.toml`, `/home/.scudo.toml`, `/home/user/.scudo.toml`, `/home/user/projects/.scudo.toml`, `/home/user/projects/myapp/.scudo.toml`.

Every top-level section is a profile, with one exception: `[scudo]` holds settings that are
about scudo itself rather than about a command — the [logging](../logging.md#logging) defaults, the
[terminal UI](../tui.md#terminal-ui) and the [lookup variables](variables.md#lookup-variables) every profile can
use. It is merged key by key across the files above like everything else, and `scudo` is
therefore not available as a profile name.

```toml
[scudo]
log.level = "info"
tui.prefix = "C-b"
tui.scrollback = 20000
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }
```

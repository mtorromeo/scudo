# Variables

## Environment variables

String values (including array elements) support `$VAR` and `${VAR}` expansion using the environment of the calling process. A reference to an undefined variable is an error.

### `$SCUDO_CONFIG_DIR`

Inside a profile, `$SCUDO_CONFIG_DIR` (also `${SCUDO_CONFIG_DIR}`) expands to the absolute path of the directory containing the config file that profile was defined in. This is resolved per file, so a profile in `/etc/scudo/config.toml` sees `/etc/scudo`, while one in a project's `.scudo.toml` sees that project directory. It is handy for referencing files that live next to the config:

```toml
[myapp]
exec = "$SCUDO_CONFIG_DIR/wrapper.sh"
systemd.BindReadOnlyPaths = ["$SCUDO_CONFIG_DIR/allowlist.txt"]
```

The value is substituted when the config is loaded, before `$arg_*` and other `$VAR` expansion. When a profile inherits values via `extend` or from a same-named profile, each inherited value keeps the config dir of the file it was written in.

### Lookup variables

The `vars` table defines variables that name a directory, found by looking for a file or directory from the current directory up to `/`: the first directory holding it is the value. A command run anywhere inside a repository can thus be given the whole repository, or the package it is in:

```toml
[scudo]
vars.PROJECT_DIR = { lookup = ".git", fallback = "cwd" }

[npm]
match = "npm"
vars.PACKAGE_DIR = { lookup = "package.json" }
filesystem.write = ["$PACKAGE_DIR/node_modules", "$PROJECT_DIR/.git"]
```

| Key | Type | Description |
|-----|------|-------------|
| `lookup` | string or array of strings | Name(s), relative to each directory, to look for; a file and a directory count alike (a worktree has a `.git` file). With several, the closest directory holding any of them wins. |
| `fallback` | `"skip"`, `"cwd"` or `"error"` | What the variable is when no directory holds any of them (default `"skip"`) |

- `skip`: the value that references the variable is dropped as if it was never written — a list loses that entry, a property or a key is left out. `"$PACKAGE_DIR/node_modules"` outside a package is gone, not `/node_modules`.
- `cwd`: the current directory.
- `error`: the command does not run. Only a variable some value actually references is looked up, so an unused one never fails.

Variables in `[scudo]` are available to every profile; a profile's own `vars` add to them and win over a same-named one, and among profiles combined together the one applied last wins, as for `args`. A lookup variable takes precedence over an environment variable of the same name. Names follow the environment variable rules, and cannot start with `arg_` or be `SCUDO_CONFIG_DIR`.

## Command argument variables

Profile values can also reference the arguments of the command being run. These variables all start with `$arg_` and are silently empty if the corresponding argument was not passed (unlike environment variables, which are an error when undefined). Empty strings produced by absent argument variables are filtered out from arrays.

### Flag variables

The `args` table names a variable and the flag(s) that fill it:

```toml
[myagent]
match = "myagent"
args.add_dir = "--add-dir"                     # one flag
args.target = ["-t", "--target-directory"]     # several spellings of it
filesystem.read = ["$arg_add_dir"]
filesystem.write = ["$arg_target"]
```

The value can be passed as `--add-dir value` or `--add-dir=value`, and every occurrence adds to the same variable: `myagent --add-dir a --add-dir b --add-dir=c` gives `$arg_add_dir` three values, which in a list become three entries.

For a flag that takes every argument after it, up to the next one starting with `-`, use the table form with `greedy = true`:

```toml
[claude]
match = "claude"
args.add_dir = { flags = "--add-dir", greedy = true }
filesystem.read = ["$arg_add_dir"]
# claude --add-dir a b c  →  $arg_add_dir = ["a", "b", "c"]
```

A greedy flag cannot tell a value from an argument that happens to follow it: in `claude --add-dir a "fix the bug"` the prompt is taken as a directory too. Paths that do not exist are skipped, so the harm is limited to that.

### Positional variables

Arguments that are neither flags nor the value of a declared flag are positional. Flags not declared in `args` never take a value, so declare every flag whose value could otherwise be mistaken for a positional:

```toml
[install]
match = "install"
args.target = ["-t", "--target-directory"]
filesystem.write = ["$arg_1"]   # first positional argument
```

| Variable | Value |
|----------|-------|
| `$arg_1` | first positional argument |
| `$arg_2` | second positional argument |
| `$arg_N` | Nth positional argument |
| `$arg_rest` | all positionals space-joined (like `$*`) |

`--` terminates option parsing; all subsequent arguments are treated as positional.

### Array expansion in string templates

When a named flag variable holds multiple values and appears inside a string template, the template is replicated once per value:

```toml
[rsync]
args.include = ["-I", "--include"]
systemd.BindReadOnlyPaths = ["/prefix/$arg_include"]
# -I a -I b  →  ["/prefix/a", "/prefix/b"]
```

Using more than one multi-value argument variable inside the same string template is an error; use separate array entries instead.

## Default values

`${NAME:-DEFAULT}` stands for `DEFAULT` when `NAME` is unset or empty, as in the shell. It works
with every kind of variable, so a profile can give an optional argument a sensible fallback:

```toml
[ls]
match = "ls"
filesystem.read = ["${arg_1:-$PWD}"]                          # ls → $PWD, ls dir → dir

[build]
match = "build"
args.out = "--out"
filesystem.write = ["${arg_out:-${PROJECT_DIR:-$PWD}/out}"]   # the argument, else the project, else the current directory
```

`DEFAULT` is itself a template — literal text, `$VAR`, or another `${…:-…}` to chain more
fallbacks — and is expanded only when it is used: a `$VAR` that is undefined in an unused default
is not an error. What counts as unset:

| Variable | Unset when |
|----------|------------|
| `$arg_*` | the argument was not passed (or only with empty values) |
| `$VAR` from the environment | it is not defined, or is empty |
| [lookup variable](#lookup-variables) | nothing is found; its own `fallback` is then not consulted |

`${arg_1:-}` is the same as `$arg_1`.

## Path canonicalization

Entries of the `filesystem` lists are always made absolute. When a variable (`$arg_*` or `$VAR`) is used inside a systemd property that expects filesystem paths (such as `BindPaths`, `ReadWritePaths`, `WorkingDirectory`, etc.), its expanded value is automatically made absolute relative to `$PWD`. This handles the common case where the user passes a relative path on the command line:

```toml
[rsync]
args.include = ["-I", "--include"]
systemd.BindReadOnlyPaths = ["$arg_include"]
# rsync -I ./src  →  BindReadOnlyPaths=/abs/cwd/src
```

Only the **expanded variable value** is canonicalized — literal text in the template is left untouched — and only when the variable opens a path: at the start of the value, after systemd's prefix characters (`-`, `+`, `!`, `!!`, `~`), or after a `:` or a space separating paths. So prefixes can be used freely in the literal part, and a variable inside a path component is inserted as it is:

```toml
[app]
systemd.ReadWritePaths = ["-$arg_1", "-/tmp/claude-$UID"]
# ./relative  →  -/abs/cwd/relative   ('-' is literal, path is made absolute)
# UID=1000    →  -/tmp/claude-1000    (the variable is part of a component)
```

A [default value](#default-values) taking a variable's place counts as the variable's value, literal text included: `${arg_1:-out}` becomes `/abs/cwd/out` when no argument is given.

Absolute paths are passed through unchanged. Canonicalization is purely lexical (it does not require the path to exist).

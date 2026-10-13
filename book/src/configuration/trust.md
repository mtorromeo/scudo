# Trust confirmation for per-directory configs

Because `.scudo.toml` files can be committed to a repository and may arrive from external sources, scudo requires explicit user approval before loading them. On first encounter scudo prints the full file contents and asks for confirmation. When a previously approved file changes, scudo shows a unified diff against the trusted version and asks again.

```
New config file: /home/user/projects/myapp/.scudo.toml

  [curl]
  PrivateNetwork = true
  MemoryMax = "256M"

Trust this config file? [y/N]
```

Approved files are recorded in `$XDG_CONFIG_HOME/scudo/trusted.toml`. Matching is done on the canonical absolute path and the exact file contents. If the user declines, scudo exits with an error rather than running the command without the intended sandboxing constraints.

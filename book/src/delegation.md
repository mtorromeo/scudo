# Delegating commands

A command started inside a sealed sandbox runs with that sandbox's access: see
[Nested calls](session-bus.md#nested-calls). For an AI coding agent that is the wrong way
round. The `npm install` it runs has the agent's access rather than npm's, so a postinstall
script reaches everything the agent was trusted with: its git credentials, its signing key,
the container socket it was given.

Instead, two settings let such commands run in a sandbox of their own:

```toml
# The tools: built to run hostile code confined.
[supply-chain]
extend = ["git-project"]
delegable = true

[npm]
extend = "supply-chain"
match = ["npm", "npx"]

# The agent: whatever it starts that has a delegable profile runs under that profile.
[agents]
extend = ["git-project"]
match = ["claude", "opencode"]
delegate = true
```

**`delegable = true`** is what the tool's profile says: it may be run on someone else's
request. It is inherited through `extend`, so it can be set once on a base profile, and
`delegable = false` takes it back for a profile that extends one. Mark only profiles meant to
contain what they run. Delegation hands over whatever the profile grants, so a profile that
grants much — an editor writing its config, anything with the container socket — would turn
every sandbox that may delegate to it into one that grants as much.

**`delegate`** is what the caller's profile says. With `true` it delegates every profile that
is `delegable` and has a `match`. It can also be given a name or a list of names, to delegate
only those. A name that does not exist, has no `match` or is not `delegable` is an error.
Both forms accumulate when profiles are combined.

A command is delegated when its name matches a delegated profile, and it then runs exactly as
it would have from a terminal, under every profile that matches it. It runs in a sandbox
*beside* the agent's, not inside it, so the agent's profile no longer has to carry each
tool's caches and credentials: it can stay as narrow as the agent itself needs.

Commands that no delegated profile matches run inside the agent's sandbox, as before. That
includes a command whose profile is not delegable.

The command line can override both for one run:

- **`--delegate`** adds every delegable profile, as `delegate = true` would, to whatever the
  profiles already delegate.
- **`--no-delegate`** delegates nothing: no broker is started, and every command runs inside
  the sandbox.

If both are given, the last one wins. Like the other options, they are refused by a scudo
started inside a sandbox, since there is nothing they could change there.

## How it works

When the agent's sandbox starts, scudo starts a **broker** outside it. The broker listens on
a socket that is bind-mounted at `/run/user/<uid>/scudo/broker` in that one sandbox; every
other broker's socket is made inaccessible. When the scudo inside is asked for a command, it
hands the broker the command, its arguments and its three standard streams. The broker
checks the request and starts scudo again, outside, which reads the configuration and runs
`systemd-run` like any other invocation. The exit code comes back the same way, and signals
the scudo inside receives are passed on to the command.

<svg class="diagram" viewBox="0 0 820 560" role="img" aria-labelledby="dg-delegation-title">
<title id="dg-delegation-title">A delegated command: the scudo inside the agent's sandbox hands the command to the broker outside, which starts it in a sandbox of its own</title>
<defs><marker id="dg-delegation-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="head" d="M0 0 10 5 0 10z"/></marker></defs>
<rect class="zone" x="16" y="16" width="232" height="528" rx="10"/>
<text class="title" x="32" y="42">agent sandbox</text>
<text class="muted mono" x="32" y="60">scudo-sealed-…a.service</text>
<rect class="box" x="36" y="84" width="192" height="44" rx="6"/>
<text x="132" y="111" text-anchor="middle">claude</text>
<rect class="box key" x="36" y="172" width="192" height="56" rx="6"/>
<text x="132" y="196" text-anchor="middle">npm install</text>
<text class="muted" x="132" y="215" text-anchor="middle">npm is a symlink to scudo</text>
<rect class="box" x="36" y="274" width="192" height="56" rx="6"/>
<text class="mono" x="132" y="298" text-anchor="middle">…/scudo/broker</text>
<text class="muted" x="132" y="317" text-anchor="middle">socket, mounted here only</text>
<text class="muted" x="132" y="392" text-anchor="middle">a command no delegable</text>
<text class="muted" x="132" y="409" text-anchor="middle">profile matches runs here,</text>
<text class="muted" x="132" y="426" text-anchor="middle">as it always did</text>
<path class="flow" d="M132 128V170" marker-end="url(#dg-delegation-arrow)"/>
<path class="flow" d="M132 228V272" marker-end="url(#dg-delegation-arrow)"/>
<text class="title" x="460" y="42" text-anchor="middle">outside any sandbox</text>
<text class="muted" x="460" y="60" text-anchor="middle">started with the agent, gone with it</text>
<text class="muted" x="460" y="214" text-anchor="middle">checks the caller's cgroup,</text>
<text class="muted" x="460" y="231" text-anchor="middle">reads its directory from /proc,</text>
<text class="muted" x="460" y="248" text-anchor="middle">matches the name to a delegable profile</text>
<rect class="box key" x="360" y="274" width="200" height="56" rx="6"/>
<text class="title" x="460" y="298" text-anchor="middle">broker</text>
<text class="muted mono" x="460" y="317" text-anchor="middle">scudo --broker</text>
<path class="flow" d="M228 292H358" marker-end="url(#dg-delegation-arrow)"/>
<text x="240" y="263"><tspan class="num">1</tspan><tspan class="muted" dx="5">command, args,</tspan></text>
<text class="muted" x="251" y="279">fds 0 1 2</text>
<path class="flow back" d="M360 314H230" marker-end="url(#dg-delegation-arrow)"/>
<text x="240" y="336"><tspan class="num">4</tspan><tspan class="muted" dx="5">exit code</tspan></text>
<rect class="box" x="360" y="384" width="200" height="56" rx="6"/>
<text class="mono" x="460" y="408" text-anchor="middle">scudo --delegated</text>
<text class="muted" x="460" y="427" text-anchor="middle">config, trust, systemd-run</text>
<path class="flow" d="M460 330V382" marker-end="url(#dg-delegation-arrow)"/>
<text x="470" y="352"><tspan class="num">2</tspan><tspan class="muted" dx="5">started in</tspan></text>
<text class="muted" x="481" y="368">its directory</text>
<rect class="zone" x="624" y="16" width="180" height="528" rx="10"/>
<text class="title" x="638" y="42">npm sandbox</text>
<text class="muted mono" x="638" y="60">scudo-sealed-…b</text>
<text class="muted" x="714" y="104" text-anchor="middle">npm's own profile:</text>
<text class="muted" x="714" y="121" text-anchor="middle">its cache, its config,</text>
<text class="muted" x="714" y="138" text-anchor="middle">none of the agent's</text>
<text class="muted" x="714" y="155" text-anchor="middle">sockets</text>
<text class="muted" x="714" y="212" text-anchor="middle">writes straight to</text>
<text class="muted" x="714" y="229" text-anchor="middle">the agent's stdout</text>
<text class="muted" x="714" y="246" text-anchor="middle">and stderr</text>
<rect class="box" x="638" y="384" width="152" height="56" rx="6"/>
<text class="mono" x="714" y="408" text-anchor="middle">--bpf-shim</text>
<text class="muted" x="714" y="427" text-anchor="middle">claims the policies</text>
<rect class="box key" x="638" y="484" width="152" height="44" rx="6"/>
<text x="714" y="511" text-anchor="middle">npm install</text>
<path class="flow" d="M714 440V482" marker-end="url(#dg-delegation-arrow)"/>
<path class="flow" d="M560 412H636" marker-end="url(#dg-delegation-arrow)"/>
<text x="572" y="402"><tspan class="num">3</tspan><tspan class="muted" dx="4">unit</tspan></text>
</svg>

The broker ends with the agent's sandbox. Delegated commands still running then are stopped,
and so is one whose caller is killed.

## What a request cannot do

The request is the agent's, and its command line is the agent's to write, so nothing in it
gets to widen what the delegated sandbox may do:

- **Only the command's name chooses the profiles.** `--profile`, `--no-match`, `-P` and the
  network flags are refused.
- **The working directory comes from the kernel**, not from the request. It has to be the
  very same directory outside the sandbox, which rules out a private `/tmp` or a hidden
  `$HOME`. It also has to lie inside something the agent can already write.
- **Paths worked out from the request are held to the same rule.** If a delegated profile
  derives a path it grants from `$PWD`, an `$arg_*`, a lookup variable or a relative path,
  that path has to lie inside what the agent can write, or the command is refused. Without
  this, a profile that writes `${arg_directory}` would turn `make -C ~` into write access to
  the whole home directory. Paths written out in full (`$HOME/.npm`) are the profile's
  policy and are not checked.
- **Nothing is asked.** The delegated command's standard input is the agent's, so a
  `.scudo.toml` that is not trusted yet, or a profile with `confirm = true`, is an error
  rather than a `[y/N]` the agent could answer.
- **The agent's environment is not passed on**, as with any `systemd-run`. Variables in the
  profiles expand with the environment scudo was started with.
- **A delegated command has to be sandboxed.** If its profiles add up to nothing, it is
  refused rather than run outside every sandbox.

A delegated command that is refused fails with the reason on its stderr, so the agent can see
why. If the broker cannot be reached at all, scudo fails too. It does not fall back to running
the command in place, because whether the command should have been delegated is the
broker's to decide.

`delegate` needs a sealed sandbox. With `dbus.session = "allow"` the sandbox could start
anything it liked anyway, and scudo refuses the combination.

## What is reported

The broker reports each request through scudo's [logging](logging.md):

| Level | |
|-------|-|
| `debug` | delegated (with the directory, the profiles and the unit), finished (with the exit code), not delegated |
| `warn` | refused, with the reason |

Without `--tui` the broker writes where the scudo that started it would: by default that is
stderr, which is the terminal the agent is drawing on. For an agent, prefer
`log.target = "journald"` or a file in its profile. With `--tui` the reports go to the context
area instead (`^A s`), which keeps the last few.

What the delegated sandbox itself turns away (its refused connections and hidden files) is
reported to the agent's stderr, beside the command's own output, for the same reason a
refusal is: the agent is the one who has to understand why the command failed.

## Limits

The broker protects against what the tools do, not against the agent. An agent that runs
`/usr/bin/npm` instead of `npm` skips scudo altogether and runs it in its own sandbox. To close
that, the agent's profile can deny the real binaries, for instance
`filesystem.deny = ["/usr/lib/node_modules/npm"]`. scudo resolves the command outside, so
delegation keeps working. Running the code a tool installed, `node ./node_modules/.bin/x`
say, also happens in the agent's sandbox unless that command is delegated too.

A `SIGTERM` passed on to a delegated command ends it with code 0: systemd counts `SIGTERM` as
a clean exit for a service, exactly as when scudo is run from a terminal.

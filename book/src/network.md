# Network filtering

`PrivateNetwork = true` is all-or-nothing. The `[profile.network]` table asks for something
finer: deny everything by default and allow only what the command actually needs. Here
`supply-chain` is the base of the
[recommended configuration](configuration/recommended.md#recommended-configuration).

```toml
[cargo]
match = "cargo"
extend = "supply-chain"

[cargo.network]
default = "deny"            # "deny" (default) or "allow"
inbound = "deny"            # "deny" (default) or "allow"
on_unavailable = "fail"     # "fail" (default), "no-network", or "warn"
log = "off"                 # "off" (default) or "denied"; "denied" is watchable
                            # even when the policy denies everything

dest = { allow = ["10.0.0.0/8", "*.crates.io"], deny = ["10.1.2.0/24"] }
ports = { allow = [443, "53/udp"], deny = [22] }
```

## The two dimensions

**`dest` and `ports` are independent sources of permission, not filters that narrow one
another.** A packet is judged by:

```text
if the destination is denied  or the port is denied   ->  deny
if the destination is allowed or the port is allowed  ->  allow
otherwise                                             ->  the default
```

Three things follow, and the second one is the one to read twice:

- **An empty `allow` list grants nothing, not everything.** A dimension with nothing in it
  abstains and the other one decides.
- **`ports.allow` opens those ports at *every* address**, including ones `dest` never mentions.
  It widens; it does not narrow. There is no way to say "port 443, but only on this host" —
  that is the price of dropping the per-rule port, and it is what lets the whole policy be two
  map lookups instead of a scan.
- **`ports.deny` is what narrows**, and it revokes everywhere — including at an address
  `dest.allow` names.

Traffic with no port of its own — ICMP, raw sockets — needs no special case: the port dimension
abstains on both sides and the destination decides alone.

## Destinations

A `dest` entry is a bare string:

| Form | Example |
|------|---------|
| CIDR | `"10.0.0.0/8"`, `"2606:4700::/32"` |
| Address | `"1.1.1.1"`, `"2606:4700::1"` |
| Host or glob | `"api.github.com"`, `"*.crates.io"` |
| Symbolic name | `"any"`, `"localhost"`, `"link-local"`, `"multicast"` |

IPv6 addresses are written plainly — there is no port to tell them apart from, so they need no
brackets. Hosts accept `*` and `?` globs, and `*` crosses dots: `*.crates.io` covers
`a.b.crates.io` but not the bare `crates.io`. A symbolic name is systemd's, and expands to its
IPv4 *and* IPv6 networks.

## Ports

A `ports` entry is a number, or a string holding a range, either of them optionally narrowed to
one protocol with a `/tcp` or `/udp` suffix:

| Form | Example |
|------|---------|
| Port | `443` |
| Range | `"8000-8100"` |
| Port and protocol | `"53/udp"` |
| Range and protocol | `"8000-8100/tcp"` |

A port written without a protocol covers TCP and UDP both.

## Order does not matter

Every entry of a list carries the same verdict, so which one matches cannot change the outcome,
and `deny` beating `allow` is a property of how the two are consulted rather than of where
rules sit. That makes merging two profiles' lists a plain union: commutative, idempotent, and
impossible to get wrong by reordering. Entries take `$VAR` and `$arg_*` expansions like any
other profile value, and each of the four lists adds to the one it inherits.

## From the command line

`--allow-dest`, `--deny-dest`, `--allow-port` and `--deny-port` change the rules for one run,
without touching the config. They take the same values as `dest` and `ports`, are repeatable
and accept comma-separated lists:

```
scudo --allow-dest api.github.com,10.0.0.0/8 --allow-port 53/udp --deny-port 22 cargo build
```

They are applied after every profile, those selected with `--profile` included, and they
**move** an entry rather than only adding it: `--allow-dest X` takes `X` out of `dest.deny` and
puts it in `dest.allow`, and `--deny-dest X` does the opposite. Without that, allowing something a
profile denied would change nothing, since a deny always wins. Entries are compared once
normalised — `localhost` stands for both of its networks, host names ignore case — and a port
is only the same rule with the same range and protocol, so `--deny-port 443` leaves an allowed
`443/tcp` alone. Allowing and denying the same entry at once is an error.

When no profile has a `network` table, the flags make a policy of their own. If any of them
allows something, it denies everything else, as `network = { ... }` would; if they only deny,
everything else stays allowed. Either way the other settings keep their defaults — the service
manager stays out of reach and `on_unavailable` is `"fail"`. When a profile does have a policy,
its `default` and `inbound` are left as they are.

Denying everything (`network = {}`) is realised with `PrivateNetwork=yes` and needs nothing
else — unless it also asks to be told what it turned away, which attaches an observer beside it;
see [Seeing what was blocked](#seeing-what-was-blocked). Anything finer needs the `scudo-bpfd` helper, which attaches eBPF programs to the
command's cgroup; systemd's own `IPAddressAllow=` and `SocketBindAllow=` are silently ignored
in user units, since `systemd --user` may not load BPF programs.

## Names

**Naming a host in `dest` is what allows that domain to be resolved**, and the DNS allowlist is
nothing more than the set of names the destination lists mention. `scudo-bpfd` answers the
sandbox's DNS itself: the eBPF programs redirect every query to a resolver bound to loopback for
that one sandbox, which refuses names no rule mentions, forwards the rest to the system's
nameservers, and records the `A` and `AAAA` addresses it hands back. From that moment those
addresses are covered by the list that named the host, as `/32` and `/128` prefixes like any
other. Both UDP and TCP queries are served, and a truncated answer is retried over TCP.

<svg class="diagram" viewBox="0 0 820 380" role="img" aria-labelledby="dg-dns-title">
<title id="dg-dns-title">How naming a host allows it: the sandbox's DNS is redirected to a resolver of its own, which answers only for names a rule mentions and adds the addresses it returns to the destination tries that every connection is checked against</title>
<defs>
<marker id="dg-dns-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="head" d="M0 0 10 5 0 10z"/></marker>
<marker id="dg-dns-deny" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="head deny" d="M0 0 10 5 0 10z"/></marker>
</defs>
<rect class="zone" x="16" y="16" width="190" height="348" rx="10"/>
<text class="title" x="32" y="42">the sandbox</text>
<rect class="box key" x="36" y="70" width="150" height="44" rx="6"/>
<text x="111" y="97" text-anchor="middle">the command</text>
<rect class="box" x="236" y="62" width="190" height="60" rx="6"/>
<text class="title" x="331" y="85" text-anchor="middle">cgroup hooks</text>
<text class="muted mono" x="331" y="104" text-anchor="middle">connect · sendmsg · skb</text>
<rect class="box key" x="478" y="62" width="180" height="60" rx="6"/>
<text class="title" x="568" y="85" text-anchor="middle">resolver</text>
<text class="muted" x="568" y="104" text-anchor="middle">one per sandbox, in bpfd</text>
<rect class="box" x="690" y="70" width="114" height="44" rx="6"/>
<text x="747" y="97" text-anchor="middle">nameservers</text>
<path class="flow" d="M186 92H234" marker-end="url(#dg-dns-arrow)"/>
<path class="flow" d="M426 92H476" marker-end="url(#dg-dns-arrow)"/>
<text class="muted" x="451" y="84" text-anchor="middle">DNS</text>
<path class="flow" d="M658 92H688" marker-end="url(#dg-dns-arrow)"/>
<path class="flow deny" d="M658 112C680 140 690 160 700 188" marker-end="url(#dg-dns-deny)"/>
<text class="muted" x="747" y="134" text-anchor="middle">names a rule</text>
<text class="muted" x="747" y="150" text-anchor="middle">mentions</text>
<text class="muted" x="747" y="206" text-anchor="middle">any other name:</text>
<text class="muted" x="747" y="222" text-anchor="middle">refused</text>
<rect class="box" x="236" y="232" width="422" height="72" rx="6"/>
<text class="title" x="447" y="256" text-anchor="middle">destination tries</text>
<text class="muted" x="447" y="275" text-anchor="middle">deny and allow × IPv4 and IPv6, longest prefix wins</text>
<text class="muted" x="447" y="292" text-anchor="middle">ports in bitmaps beside them; no loop, no rule limit</text>
<path class="flow" d="M610 122V230" marker-end="url(#dg-dns-arrow)"/>
<text class="muted" x="620" y="194">adds A, AAAA</text>
<text class="muted" x="620" y="211">as /32, /128</text>
<path class="flow" d="M331 122V230" marker-end="url(#dg-dns-arrow)"/>
<text class="muted" x="341" y="194">every connection:</text>
<text class="muted" x="341" y="211">deny first, then allow</text>
<path class="flow deny" d="M234 268H120V116" marker-end="url(#dg-dns-deny)"/>
<text class="muted" x="128" y="152">refused:</text>
<text class="muted mono" x="128" y="170">EPERM</text>
<text class="muted" x="447" y="336" text-anchor="middle">a learnt address is removed when its TTL runs out (30 s to 1 h);</text>
<text class="muted" x="447" y="353" text-anchor="middle">what the config names outright is never removed</text>
</svg>

The redirect happens before any check, so a policy whose port lists never mention 53 still
resolves names — and, for the same reason, `ports.deny = [53]` does not take that away: the
query never reaches the port rules, because it never reaches port 53. What decides which names
may be looked up is the set of names the destination rules mention, and nothing else. A policy
that names no host gets no resolver at all, and then port 53 is judged like any other port.

Three things follow from this design, and all three are deliberate:

- **The rule is matched against the question, not the CNAME chain**, so a rule for
  `api.github.com` covers whatever that name ends up resolving to.
- **A name in `dest.deny` still resolves.** That is how its addresses become known, so the rule
  keeps them out of reach even for a program that had the address hardcoded. Since the deny
  side is consulted first, the connection fails either way.
- **A name no rule mentions is refused — unless refusing it would buy nothing.** With
  `default = "allow"`, with a destination covering the whole address space (`any`,
  `0.0.0.0/0`), or with any `ports.allow` at all — each of these already lets the command reach
  an address it never named, so refusing the lookup would only break it.

Addresses learnt this way expire with the record's TTL, clamped to between 30 seconds and an
hour — a zero TTL would otherwise expire the address before the program managed to connect.
Expiry is a *removal*: the resolver takes the prefix back out, and the programs carry no expiry
check of their own. That is not an oversight. A prefix that had expired but was still present
would keep covering the shorter prefixes underneath it, with no way to fall back to the
next-longest match — so a stale `/32` in the deny trie would read as "no match" and let traffic
through. With removal alone, a sweep that runs late merely leaves an entry doing what it was
already doing for another half second, which errs the safe way in both directions.

A DNS-over-HTTPS or DNS-over-TLS resolver bypasses this entirely, but not the address rules:
its server has to be in the allowlist like anything else.

## How it is enforced

`scudo-bpfd` attaches four `cgroup/sock_addr` programs (`connect4`, `connect6`, `sendmsg4`,
`sendmsg6`) so a blocked destination fails with a clean `EPERM` at `connect()` rather than
timing out, plus a `cgroup_skb` egress program as a backstop — the only layer that also covers
raw sockets, ICMP and anything that is neither TCP nor UDP. With `inbound = "deny"` an ingress
program matches the *source* address, and the source port, against the same two lists, the way
`IPAddressAllow=` does, so replies from an allowed peer still arrive. `recvmsg4` and `recvmsg6`
put the source of a redirected DNS reply back to the nameserver the query was sent to — the
address is remembered per socket, keyed by its cookie, when the query is redirected — so a stub
resolver on an unconnected socket, which checks that the answer came from the server it asked,
does not throw it away.

Programs are attached as BPF links, which stack: the kernel combines the verdicts of every
program on a cgroup with a logical AND, so a second policy on the same cgroup can only ever
narrow what is permitted, never widen it.

Profiles with an enforced policy also get `ProtectControlGroups=yes`, which keeps the command
from migrating out of the cgroup the programs are attached to, and one that needs the resolver
loses systemd-resolved's varlink sockets, since a lookup made through `nss-resolve` would
neither obey the allowlist nor teach the policy the address it resolved to. A profile that sets
`ProtectControlGroups` itself keeps its own value, and is warned that the policy can then be
walked around — unless the value is `private` or `strict`, which confine it at least as well.
`private` still lets the command into sub-cgroups of its own: the network programs follow it
there, the filesystem report does not, so a profile that only reports is warned about it.

None of this holds if the command can leave its cgroup — by asking `systemd --user` for a
sibling unit, for one, which has a network and no program of ours attached. Every sandbox is
kept in its cgroup whether it has a network policy or not; see [Session bus](session-bus.md#session-bus).

## Installing the helper

```bash
sudo install -m755 target/release/scudo-bpfd /usr/bin/scudo-bpfd
sudo setcap cap_bpf,cap_net_admin,cap_perfmon=ep /usr/bin/scudo-bpfd
systemctl --user enable --now scudo-bpfd.socket
```

The daemon is socket-activated, so **`scudo-bpfd.socket` must be enabled and active in
`systemctl --user`** (`systemctl --user status scudo-bpfd.socket` tells): without it scudo
cannot reach `scudo-bpfd`, and every policy that needs it is handled by `on_unavailable`.

The daemon holds `CAP_BPF` and `CAP_NET_ADMIN` as file capabilities, so anyone on the system
can execute it. `CAP_PERFMON` is a third it can do without: it is needed only to load the
tracepoint programs behind [file access reporting](filesystem.md#seeing-what-the-filesystem-restrictions-hid),
and a daemon started without it does everything else and says so when that one thing is asked
for. What keeps that harmless is that it offers exactly one operation — *add*
restrictions to a cgroup the caller already owns — and no way to remove them: policies are
detached only when the cgroup itself disappears. It refuses any cgroup outside the calling
user's own systemd subtree, which it establishes from `SO_PEERCRED` rather than from anything
the caller says.

Registration happens in two steps for a reason. `scudo` registers the policy and gets a
single-use token; the command is then started as `scudo --bpf-shim <token> -- <command>`, and
that shim — running inside the unit, in the final cgroup — claims the token and only then
execs the real command. The cgroup does not exist before the unit starts, so registering
earlier is impossible, and attaching afterwards would leave a window in which the command runs
unfiltered.

Since the shim reaches the daemon from inside the unit, scudo bind-mounts the daemon's socket
there, read-only, whenever a policy needs it. A profile that hides `$XDG_RUNTIME_DIR` does not
have to give it back, and nothing inside can replace it.

<svg class="diagram" viewBox="0 0 820 560" role="img" aria-labelledby="dg-bpfd-title">
<title id="dg-bpfd-title">How a sandbox with a network policy starts: scudo registers the policy and gets a token, the shim inside the unit claims it, and only then the command runs</title>
<defs><marker id="dg-bpfd-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="head" d="M0 0 10 5 0 10z"/></marker></defs>
<rect class="box key" x="16" y="16" width="168" height="52" rx="6"/>
<text class="title" x="100" y="38" text-anchor="middle">scudo</text>
<text class="muted" x="100" y="56" text-anchor="middle">becomes systemd-run</text>
<rect class="box key" x="226" y="16" width="168" height="52" rx="6"/>
<text class="title" x="310" y="38" text-anchor="middle">scudo-bpfd</text>
<text class="muted" x="310" y="56" text-anchor="middle">CAP_BPF, CAP_NET_ADMIN</text>
<rect class="box key" x="436" y="16" width="168" height="52" rx="6"/>
<text class="title" x="520" y="38" text-anchor="middle">the unit</text>
<text class="muted" x="520" y="56" text-anchor="middle">its own cgroup</text>
<rect class="box key" x="636" y="16" width="168" height="52" rx="6"/>
<text class="title" x="720" y="38" text-anchor="middle">watcher</text>
<text class="muted mono" x="720" y="56" text-anchor="middle">scudo --bpf-watch</text>
<path class="lane" d="M100 68V546M310 68V546M520 68V546M720 68V546"/>
<path class="flow" d="M100 100H308" marker-end="url(#dg-bpfd-arrow)"/>
<text class="mono" x="204" y="93" text-anchor="middle">Register(policies)</text>
<path class="flow back" d="M310 130H102" marker-end="url(#dg-bpfd-arrow)"/>
<text class="mono" x="204" y="123" text-anchor="middle">token</text>
<path class="flow" d="M100 168H718" marker-end="url(#dg-bpfd-arrow)"/>
<text class="muted" x="620" y="161" text-anchor="middle">spawns, if reporting</text>
<path class="flow" d="M720 200H312" marker-end="url(#dg-bpfd-arrow)"/>
<text class="mono" x="620" y="193" text-anchor="middle">Watch(token)</text>
<rect class="box" x="30" y="222" width="140" height="30" rx="6"/>
<text class="mono" x="100" y="242" text-anchor="middle">exec systemd-run</text>
<path class="flow" d="M100 276H518" marker-end="url(#dg-bpfd-arrow)"/>
<text class="muted" x="400" y="269" text-anchor="middle">starts it</text>
<rect class="box" x="445" y="292" width="150" height="30" rx="6"/>
<text class="mono" x="520" y="312" text-anchor="middle">scudo --bpf-shim</text>
<path class="flow" d="M520 346H312" marker-end="url(#dg-bpfd-arrow)"/>
<text class="mono" x="416" y="339" text-anchor="middle">Attach(token)</text>
<rect class="box" x="210" y="362" width="200" height="44" rx="6"/>
<text x="310" y="380" text-anchor="middle">attaches the programs</text>
<text class="muted" x="310" y="397" text-anchor="middle">to the shim's cgroup</text>
<path class="flow back" d="M310 424H518" marker-end="url(#dg-bpfd-arrow)"/>
<text class="mono" x="416" y="417" text-anchor="middle">Attached</text>
<rect class="box key" x="445" y="440" width="150" height="30" rx="6"/>
<text class="mono" x="520" y="460" text-anchor="middle">exec the command</text>
<path class="flow" d="M310 488H718" marker-end="url(#dg-bpfd-arrow)"/>
<text class="muted" x="620" y="481" text-anchor="middle">refusals</text>
<rect class="box" x="645" y="504" width="150" height="30" rx="6"/>
<text x="720" y="524" text-anchor="middle">prints to stderr</text>
</svg>

**When the policy cannot be enforced** — the helper is not installed, lacks its capabilities,
`scudo-bpfd.socket` is not active in `systemctl --user`, or the kernel does not support it — `on_unavailable` decides what happens:

| Value | Behaviour |
|-------|-----------|
| `fail` (default) | The command does not run. |
| `no-network` | The command runs with no network at all. |
| `warn` | A warning is printed and the command runs unfiltered. |

The default is fail-closed: a profile that asks for a network policy never silently runs
without one.

## Seeing what was blocked

A denied connection reaches the command as a bare `EPERM`, and a denied packet as nothing at
all, so a policy that is one rule too tight looks like a program that is simply broken.
`--verbose`, or `log = "denied"` on the profile, turns every refusal into a line on stderr:

```console
$ scudo --verbose -- curl -sS https://example.com/
scudo: warning: blocked DNS lookup of example.com (no rule names it)
scudo: warning: blocked connect to 1.1.1.1:443/tcp
scudo: curl: blocked example.com (2x), 1.1.1.1:443 (7x) [5 repeats suppressed]
```

Mixed into the command's own output, those lines are easy to lose; the
[terminal UI](tui.md#terminal-ui) puts them in a panel of their own instead:

```console
$ scudo --tui -- curl -sS https://example.com/
```

Each refusal is a `warn` event and the closing summary an `info` one, so they follow whatever
[logging](logging.md#logging) is configured. On journald they carry the address, port, stage and
transport as fields of their own, which is what makes them filterable there:

```console
$ journalctl -t scudo F_STAGE=connect -o json | jq -r '.F_ADDR + ":" + .F_PORT'
```

Refused DNS lookups are on the same stream, and usually come first: naming a host in a rule is
also what permits resolving it, so a missing rule shows up as a name that will not resolve long
before any address is reached.

Reporting is off unless asked for. It costs a ring buffer per sandbox and a small process to
read it, and with it off the emit sites are folded out of the eBPF programs entirely, so a
sandbox nobody is watching pays nothing. Repeats of the same refusal within a few seconds are
collapsed into one line — a denied connection is retried, and one `curl` would otherwise fill
the screen — and the closing summary counts every attempt, including the ones that were never
printed.

A policy that denies everything is realised by taking the network away rather than by attaching
anything, so on its own it has nothing to report from. Asking to be told is what changes that:
an *observer* is attached beside the empty namespace, allowing `localhost` and denying the rest
— which is exactly what that namespace already permits, so nothing is enforced that was not
enforced before and loopback keeps working without reporting itself. The cgroup hooks are not
scoped to a network namespace, which is what lets them see refusals inside one.

The observer is reporting and nothing else, so losing it costs only the reporting: if
`scudo-bpfd` cannot be reached, `on_unavailable` does **not** apply — the command runs, with the
network still taken away, and a warning says the refusals will not be named. `scudo-bpfd` is
needed to *watch* a deny-all policy; it is never needed to *enforce* one.

# tsf-cybersec

Security scanners for a device under test, packaged as an external Test
Environment (TE) repository and consumed with the `TE_EXT_REPO` builder
directive.

Library:

- `tapi_cybersec` — engine-side scanners, built as a shared library:
  - `tapi_binscan` — how a binary on the agent was built: PIE, NX,
    RELRO, stack protector, FORTIFY, RPATH, text relocations, W+X;
  - `tapi_netexpose` — what the agent listens on, and what of it another
    agent can reach;
  - `tapi_egress` — what the agent talks to, against what it is allowed
    to talk to;
  - `tapi_sniffrules` — ready-made rules over captured traffic for the
    usual protocol mistakes;
  - `tapi_objdump` — what is actually in the code, through binutils;
  - `tapi_frida` — what the code actually does, and making it take the
    path it will not take by itself;
  - `tapi_cybersec.h` — the finding and report model they share.

It builds on [tsf-kernel](https://github.com/interpretica-io/tsf-kernel)
and [tsf-devtool](https://github.com/interpretica-io/tsf-devtool), for
reading kernel interfaces and for running tools on an agent.

The scanners read state and report; nothing here changes the device or
exploits what it finds. The two reverse engineering tools are the
exception that proves the rule: Frida does change the process it is
attached to, deliberately, and it is test equipment in exactly the sense
the kernel probes of tsf-kernel are — it never ships with the product,
it runs on a lab machine, and it exists to make a defect observable so
that it can be closed.

## Usage

Declare the repositories in an external libraries catalog and pass it to
`dispatcher.sh --ext-libs=ext-libs.yml`:

```yaml
repositories:
  - name: tsf_devtool
    url: https://github.com/interpretica-io/tsf-devtool.git
    ref: <tag>
    libs: [ tapi_devtool ]
  - name: tsf_kernel
    url: https://github.com/interpretica-io/tsf-kernel.git
    ref: <tag>
    libs: [ tapi_kernel ]
  - name: tsf_cybersec
    url: https://github.com/interpretica-io/tsf-cybersec.git
    ref: <tag>
    libs: [ tapi_cybersec ]
```

Bind them in `builder.conf`, and make sure TAD has the layers the
traffic rules need:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_kernel], [], [tapi_kernel])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])

TE_LIB_PARMS([tapi_tad], [], [], [--with-eth --with-ipstack])
```

Then add `tapi_cybersec` to `te_libs` in the suite's `meson.build`.

Requires TE with `TE_EXT_REPO` support, and an **RPC** job factory
(`ta_rpcprovider` on the agent).

## Findings

A scanner never fails the test itself. It appends to a
`tapi_cybersec_report`, so one run reports everything it found rather
than the first thing, and the test decides what is worth failing over:

```c
tapi_cybersec_report report;
te_string verdict = TE_STRING_INIT;

tapi_cybersec_report_init(&report);
CHECK_RC(tapi_binscan_check(ta, "/usr/sbin/dutd", NULL, &report));
CHECK_RC(tapi_netexpose_check(factory, NULL, allowed,
                              TE_ARRAY_LEN(allowed), &report));
tapi_cybersec_report_log(&report);

if (tapi_cybersec_report_verdict(&report, TAPI_CYBERSEC_SEV_HIGH, &verdict))
    TEST_VERDICT("%s", verdict.ptr);
```

A verdict names the check and its subject and nothing that varies
between runs — no counts, no timestamps — so `conf/trc.xml` can match it
and a known issue stays a known issue while it is being fixed.

## tapi_binscan — how a binary was built

The binary is fetched to the engine and its ELF structure is read there:
program headers for NX, RELRO and W+X, the dynamic section for RPATH,
RUNPATH and bind-now, the symbol tables for the stack protector and
FORTIFY.

Nothing is needed on the agent — no `readelf`, no `checksec` — and
nothing is run there. Every field is taken by offset and byte order, so
a big-endian MIPS binary reads correctly from an x86 engine, which is
the usual case for an embedded DUT.

```c
tapi_binscan_info info;

CHECK_RC(tapi_binscan_inspect(ta, "/usr/sbin/dutd", &info));
tapi_binscan_info_log(&info, "/usr/sbin/dutd");
tapi_binscan_info_free(&info);
```

Checks are driven by a `tapi_binscan_policy`; the default requires PIE,
NX, full RELRO and a stack protector, and objects to RPATH, RUNPATH,
text relocations and writable executable segments. A RPATH that is not
an absolute path is reported as its own, more severe finding, because it
is the one an attacker can aim at.

This reads how the binary was built. It does not look up known
vulnerabilities: that is a question about versions and a vulnerability
database, not about the file. File permissions — setuid, setgid,
world-writable — are a property of the filesystem rather than of the
ELF, and are not covered here either.

## tapi_netexpose — what is listening, what is reachable

Two views, and a test wants both.

**From the inside**, by reading `/proc/net/tcp`, `tcp6`, `udp` and
`udp6`: every listener, with the address it is bound to and the user
that owns it. Exact, and one command.

```c
static const tapi_netexpose_allowed allowed[] = {
    { IPPROTO_TCP, 22,   false },
    { IPPROTO_TCP, 8080, true  },   /* management, loopback only */
};

CHECK_RC(tapi_netexpose_check(factory, NULL, allowed,
                              TE_ARRAY_LEN(allowed), &report));
```

A listener nobody declared is `net.unexpected-listener`; a service that
should be loopback-only and turns up on `0.0.0.0` is
`net.listens-beyond-loopback`, which is the finding this exists for.

**From the outside**, by connecting to ports from another agent — a TCP
connect scan built on `tapi_rpc` sockets. No `nmap`, nothing installed
on either side, and every connection comes from a Test Agent the suite
already owns.

```c
static const uint16_t expected[] = { 22, 443 };

CHECK_RC(tapi_netexpose_scan_check(pco_tst, dut_addr, 1, 1024, 500,
                                   expected, TE_ARRAY_LEN(expected),
                                   &report));
```

Comparing the two views is where it gets useful: a port the inside view
shows as bound and the outside view cannot reach is a firewall doing its
job; the other way round is a surprise.

Addresses in `/proc/net` are printed as native words, so reading them
back needs to know the byte order of the agent. It is not guessed —
`tapi_netexpose_opt::agent_big_endian` says so — because a guess that is
right nearly always is worse than a switch: the rare wrong answer looks
exactly like a real finding.

## tapi_egress — what it talks to

A device that reaches out to somewhere nobody expected is one of the few
signals that is both cheap to collect and hard to argue with: a
telemetry endpoint nobody declared, an update server contacted over
plain HTTP, a resolver that is not the configured one, a connection that
only appears once a particular feature is switched on.

```c
static const tapi_egress_rule rules[] = {
    { IPPROTO_UDP, "10.0.0.53/32", 53,  53  },
    { IPPROTO_TCP, "10.0.0.0/8",   443, 443 },
};
static const tapi_egress_policy policy = {
    .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
    .allow_loopback = true,
};

CHECK_RC(tapi_egress_check(factory, NULL, &policy, &report));
```

This is the socket-table view: precise, and limited to the connections
the agent's own stack has. Traffic from another namespace, or from the
kernel itself, shows up on the wire instead — and the same policy works
there, through the traffic rules below.

## tapi_sniffrules — rules over captured traffic

TE already knows how to capture: CSAPs, patterns, the sniffer. What it
does not carry is an opinion about what is wrong with what it captured.
That is what this is — a capture window with rules attached, and
findings on the other side.

```c
tapi_sniffrules_opt opt = tapi_sniffrules_default_opt;
tapi_sniffrules_session *session = NULL;

opt.rules |= TAPI_SNIFFRULE_UNEXPECTED_EGRESS;
opt.egress = &policy;

CHECK_RC(tapi_sniffrules_start(ta, "eth0", &opt, &session));
... drive the device under test ...
CHECK_RC(tapi_sniffrules_stop(session, &report));
```

| Rule | What it catches |
|---|---|
| `TAPI_SNIFFRULE_CLEARTEXT_PROTO` | telnet, FTP, HTTP, POP3, IMAP, LDAP, SNMP, TFTP, syslog, VNC, MQTT, redis, memcached |
| `TAPI_SNIFFRULE_CLEARTEXT_CREDS` | HTTP basic auth, and the login commands of FTP, POP3 and IMAP |
| `TAPI_SNIFFRULE_WEAK_TLS` | a server that agreed to something older than TLS 1.2, or any SSL handshake |
| `TAPI_SNIFFRULE_PLAINTEXT_DNS` | name resolution anyone on the path can read and rewrite |
| `TAPI_SNIFFRULE_NAME_LEAK` | mDNS, LLMNR, NetBIOS name service, SSDP |
| `TAPI_SNIFFRULE_UNEXPECTED_EGRESS` | a conversation started towards somewhere the policy does not allow |

Four things about how the rules behave:

- **Findings are deduplicated** by what they are about, so a rule that
  matches a thousand packets of one flow reports one finding.
- **The credentials rule never records the value it matched.** It names
  the flow and the fact. A test log is not a place to put a password.
- **The weak-TLS rule judges the ServerHello**, because that is what
  carries what was actually agreed. TLS 1.3 keeps `0x0303` in that field
  and moves the real version into an extension, so the rule sees TLS 1.3
  as 1.2 and reports neither; what it catches is TLS 1.1 and older,
  which is the finding worth having.
- **The egress rule judges only the first packet of a conversation** — a
  TCP SYN without an ACK, or any UDP packet — so a flow produces one
  finding and traffic that merely passes the interface the other way is
  not mistaken for the device reaching out.

The capture needs TAD built with the Ethernet and IP stack layers; see
the `TE_LIB_PARMS` line above.

## tapi_objdump — what is in the code

`tapi_binscan` answers how a binary was built by reading its ELF
structure. This answers what is actually in the code, through binutils.
They do not overlap: symbols and headers come from the ELF reader, which
needs nothing installed anywhere; disassembly comes from here.

```c
tapi_objdump_opt opt = tapi_objdump_default_opt;

opt.path = "/usr/sbin/dutd";
CHECK_RC(tapi_objdump_check_banned(factory, &opt, NULL,
                                   TAPI_DEVTOOL_TIMEOUT_MS, &report));
```

The disassembly is walked keeping track of which function each line
belongs to, so a finding names the caller — which is what makes it
actionable. `tapi_objdump_default_banned` is the list: the functions
with no bound on what they write, the ones that hand a string to a
shell, predictable randomness, and guessable temporary names.

It reports a *reference*, not a proven call: a reference inside a branch
that never runs still shows up. Confirming that it runs is what Frida is
for, and the two share the same list of names on purpose.

`objdump` runs on the agent behind the factory and reads a path on that
agent. For a device with no binutils — the usual case — copy the binary
to an agent that has them with `tapi_file_copy_ta()` first; an agent on
the engine host will do, and for a cross target it is the one place the
cross binutils are. Name the toolchain and the `objdump` of its
`cross_compile` prefix is used.

## tapi_frida — what the code does

```c
tapi_frida_opt opt = tapi_frida_default_opt;
te_string script = TE_STRING_INIT;
te_string path = TE_STRING_INIT;
tapi_frida_app *app = NULL;

tapi_frida_script_trace_calls(tapi_objdump_default_banned, &script);
CHECK_RC(tapi_frida_script_put(ta, script.ptr, &path));

opt.target_name = "dutd";
opt.script_path = path.ptr;

CHECK_RC(tapi_frida_create(factory, &opt, &app));
CHECK_RC(tapi_frida_start(app));
... drive the device under test ...
CHECK_RC(tapi_frida_stop(app));
CHECK_RC(tapi_frida_check_banned_calls(app, &report));
```

Four scripts are generated for you, and they are ordinary Frida
JavaScript — read them, change them, or write your own and pass the path:

| Script | What it does |
|---|---|
| `tapi_frida_script_trace_calls()` | reports every call to a list of functions, with the call site from the backtrace |
| `tapi_frida_script_fail_call()` | replaces the return value of the *n*th call and sets `errno`, so the error path nobody exercises gets exercised |
| `tapi_frida_script_trace_open()` | reports every file the target opens, through `open`, `open64`, `openat` and `fopen` |
| `tapi_frida_script_trace_connect()` | reports every address the target connects to |

Each prints lines with a stable prefix, which `tapi_frida_events()`
collects back into records. Two checks turn those into findings:
`tapi_frida_check_banned_calls()`, and `tapi_frida_check_egress()`,
which takes the same `tapi_egress_policy` as the socket-table scanner
and the traffic rules. That last one sees what the socket table can
miss: a connection opened and closed between two snapshots still shows
up.

`tapi_frida_script_fail_call()` is the userspace twin of the kernel
fault-injection probe: the kernel's own mechanisms cannot reach a
`malloc` inside one process, and a test that never makes an allocation
fail never learns what happens when one does.

Frida injects itself into the target. It changes timing, it can crash
the process, and attaching needs permission to `ptrace` — on a hardened
kernel `kernel.yama.ptrace_scope` refuses it, which
`tapi_kernel_security_posture_get()` will have recorded. Check it is
there at all with `tapi_frida_check_available()` and `TEST_SKIP` when it
is not.

The generated scripts are written for Linux and glibc or musl: they read
`sockaddr` the way Linux lays it out and set `errno` through
`__errno_location`.

## Static and dynamic together

The two tools answer different halves of one question, and a test that
uses both gets a result neither gives alone:

| | `tapi_objdump` | `tapi_frida` |
|---|---|---|
| needs | binutils on some agent | `frida` on the agent, `frida-server` on the DUT, `ptrace` allowed |
| target | the file | the running process |
| a `strcpy` finding means | the binary references it | it ran, from here, during this test |
| finding | `binary.banned-call`, MEDIUM | `runtime.banned-call`, HIGH |

Run the static check over every shipped binary, and the dynamic one over
the handful of paths the test can actually drive. A static finding the
dynamic run confirms is a defect with a reproducer; one it does not
reach is still worth fixing, but it is not the one to fix first.

## Scope

These scanners point at the agents, binaries and addresses the suite's
own configuration describes. That is the engagement they belong to;
pointing them anywhere else is outside it. The traffic rules want a lab
network where every party is part of that engagement, and Frida wants a
machine you are allowed to crash.

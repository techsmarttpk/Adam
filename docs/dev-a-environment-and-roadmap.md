# Dev A — Environment Checklist & Implementation Roadmap

**Scope:** Sandbox Controller · VirtualBox Integration · Guest Agent · Malware
Execution Workflow · Collectors · Raw Event Generation · Event Bus Integration ·
Orchestrator · Configuration for VM execution.

This document assumes `ARCHITECTURE.md` as the frozen source of truth. Every
section below cites the architecture section it implements. Nothing here
redesigns anything — it operationalises §5.2, §5.3, §8, §12 and your slice of
§9/§10.

---

## Part 1 — Environment Checklist

Work through this top to bottom. Items are ordered by dependency: you can't
configure networking before VirtualBox exists, can't install Sysmon before the
VM exists, and so on. Don't skip ahead — most "it works on my machine" pain in
sandbox projects comes from environment steps done out of order.

### 1. Python 3.11 environment

**Why.** §4.3 (C3) fixes Python 3.11 as the floor — you'll use `asyncio.TaskGroup`
(clean structured concurrency for the sandbox FSM's parallel operations) and
`tomllib` (stdlib TOML parsing for config, no extra dependency). Code written
against 3.10 semantics will subtly misbehave in task-group error propagation.

**Install.** Use `pyenv` (Linux/macOS) or the official python.org installer
(Windows) — not the Microsoft Store build, which sandboxes the interpreter's
filesystem access in ways that fight subprocess-heavy code like yours. Pin the
exact patch version in a `.python-version` file once the team agrees one.

```bash
pyenv install 3.11.9
pyenv local 3.11.9
python -m venv .venv
source .venv/bin/activate      # .venv\Scripts\activate on Windows
python -m pip install --upgrade pip
```

**Configure.** One venv per developer, never committed. Install your slice's
dependencies as you introduce them into `requirements.txt` under the `# core`
and `# collectors` headers already scaffolded there — alphabetical, one per
line, per §10.2.

**Common mistakes.** Mixing a system Python with a venv Python in the same
shell session (check `which python` before every debugging session). Installing
packages globally with `sudo pip install` — this has bitten more sandbox
projects than any actual malware has.

### 2. VirtualBox

**Why.** §15.3 names VirtualBox as the hypervisor; §5.2 wraps `VBoxManage`
behind `ISandboxController`. Version drift between VirtualBox and the
Extension Pack is the single most common source of "works today, broken
tomorrow" in this stack.

**Install.** Use VirtualBox 7.0.x LTS, not the latest point release — check
[virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads) for
the current LTS designation before installing, since VirtualBox's release
cadence means "latest" and "LTS" are not always the same build. Install the
matching **Extension Pack** (same version number as the base install) — it's
what gives you USB passthrough and, more relevantly, better guest control
performance.

**Configure.** Confirm `VBoxManage` is on `PATH`:

```bash
VBoxManage --version
```

Record the resolved path in `config/default.toml` under `[sandbox]
vbox_manage_path` rather than assuming it's on every developer's `PATH` —
Windows installs it to `C:\Program Files\Oracle\VirtualBox\` by default, which
is not always exported to shell `PATH` for non-interactive processes.

**Common mistakes.** Installing the Extension Pack version mismatched to the
base VirtualBox version (VirtualBox will refuse to load it, silently disabling
features you need). Running VirtualBox as one user and `VBoxManage` as another
(e.g., one via GUI, one via a service account) — VM state/lock files become
inconsistent between the two.

### 3 & 4. Windows VM and Windows version

**Why.** The guest is where Sysmon, ProcMon, and the malware itself run. §1.3
explicitly puts VirtualBox anti-detection out of scope, so the guest doesn't
need to be exotic — it needs to be **standard, reproducible, and match the
`vm_profile` config referenced in §12.2** (`config/vm_profiles/win10-x64-office.toml`).

**Recommendation.** Windows 10 22H2 x64, not Windows 11. Reasoning: it's the
most-targeted version in current malware corpora, has a smaller resource
footprint (matters when you're running 4+ VMs in parallel across the team),
and doesn't carry Windows 11's TPM/Secure Boot virtualisation requirements,
which add friction inside VirtualBox for no analytical benefit.

**Install.** Use Microsoft's official evaluation media — the [Windows 10
Enterprise evaluation
ISO](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)
is free, legitimate, and licensed for exactly this kind of isolated technical
evaluation (90-day eval period, renewable via `slmgr /rearm` a limited number
of times, or just re-provisioned from a fresh snapshot when it expires — which
you'll be doing anyway for hygiene). Do not use a personal or pirated Windows
license; licensing terms for detonating malware under a retail key are murky
and not worth the risk to a published research project. This isn't legal
advice — if your institution has a volume-license agreement covering research
VMs, check with them, since that may be a cleaner option than eval media.

**Configure.** Fresh install → apply the "recommended VM settings" in item 15
before touching anything else → **do not run Windows Update** to full
patch level. A partially-patched, realistic-vintage Windows install is
actually more representative of a real target than a fully patched one, and
patching burns hours you don't have. Install Office (per the `win10-x64-office`
profile name in §9) if your rule corpus expects Office-based lures — check
with Dev C before spending time on this.

**Common mistakes.** Installing Windows 11 because it's "the current version"
— it will cost you the TPM/vTPM fight for no analytical upside. Fully
patching the VM, which closes off exactly the vulnerabilities malware samples
in a teaching corpus are likely to target.

### 5. Sysmon installation

**Why.** §5.3, §7.2 — Sysmon is your highest-fidelity, near-real-time source
(`RawEvent.source = "SYSMON"`), covering process creation, registry, file, and
network events via ETW.

**Install (in the guest).** Download from [Sysinternals — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Install as a service with a configuration file, not with defaults:

```powershell
sysmon64.exe -accepteula -i sysmon-config.xml
```

**Configure.** Start from the community-maintained [SwiftOnSecurity Sysmon
config](https://github.com/SwiftOnSecurity/sysmon-config) rather than writing
one from scratch — it has sane include/exclude filters that avoid drowning
you in noise from Windows' own background chatter. Trim it down to the event
IDs your `adam/collectors/sysmon.py` actually maps to `RawEvent.category`
(§7.2: `PROCESS`, `FILE`, `REGISTRY`, `NETWORK`, `MODULE`, `WMI`). Store the
final config XML in `config/` (or a `sysmon/` subfolder) so it's
version-controlled, not something living only inside the VM.

**Common mistakes.** Using the stock Sysmon config with no filtering — you'll
get hundreds of thousands of events per minute from normal Windows background
activity, blowing straight through the §3.4 latency budget before your
collector even starts parsing. Forgetting Sysmon logs to the **Windows Event
Log** (`Microsoft-Windows-Sysmon/Operational` channel), not a flat file — your
collector needs to read via the Event Log API or export to EVTX, not tail a
text file that doesn't exist.

### 6. ProcMon (Process Monitor)

**Why.** §5.3 — complements Sysmon with lower-level, higher-volume file/registry
detail useful for correlation in Fusion later. §7.3's `FILE_DROPPED` example
correlates exactly this kind of multi-event join.

**Install (in the guest).** Sysinternals Process Monitor, run non-interactively:

```powershell
procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\ADAM\procmon.pml
```

**Configure.** Always run with `/BackingFile` pointed at a fixed path your
agent knows about — without it, ProcMon buffers in memory only and you lose
everything on a crash or forced teardown. Apply a filter set (`/LoadConfig`)
that excludes ADAM's own agent process and Windows Defender to cut noise. The
backing `.pml` file is binary; it needs conversion (`/OpenPML ... /SaveAs
... .csv` or `procmon.exe -OpenPML file -CSV`) before your
`adam/collectors/parsers/pml.py` can read it — **this conversion step only
completes reliably after ProcMon has been cleanly stopped**, not mid-capture.

**Common mistakes.** Reading the `.pml` backing file while ProcMon still has it
open — you'll get a truncated or locked read. Forgetting `/Quiet
/Minimized` — without them, ProcMon pops a GUI and an EULA dialog that will
silently hang your first few detonation attempts until you notice the VM
"isn't responding" because it's sitting behind a dialog box.

### 7. Wireshark / dumpcap

**Why.** §5.3, §15.3 — network telemetry for `RawEvent.category = "NETWORK"`
and eventually for the pcap artefact referenced in §16.2.

**Install (in the guest).** Install Wireshark, which bundles `dumpcap.exe` and
the Npcap driver. You only need `dumpcap`, the headless capture component —
you will never open the Wireshark GUI inside the guest during an actual run.

```powershell
dumpcap.exe -i "Ethernet" -w C:\ADAM\capture.pcap -f "not port 3389"
```

**Configure.** During Npcap install, choose **"WinPcap API-compatible mode"**
only if something in your toolchain still needs it (usually not) — otherwise
plain Npcap is fine and lighter. Exclude your own agent's HTTP traffic and RDP
(if you use it for debugging) from the capture filter so you're not capturing
ADAM's own control channel as if it were malware traffic. Capture on the
correct interface — a VM typically has one, but confirm with `dumpcap -D`
inside the guest rather than assuming index 1.

**Common mistakes.** Requiring administrator elevation for packet capture and
not granting it to the account the agent runs as — capture silently fails or
throws a permissions error your collector then has to handle. Capturing on
"any" interface and getting loopback/virtual adapter noise mixed into malware
traffic.

### 8. PowerShell requirements

**Why.** §4.3 (C4) — the guest agent is PowerShell 5.1 compatible, deliberately
not assuming .NET Core / PowerShell 7, because Windows 10 ships 5.1 out of the
box and you don't want an extra install step (and extra attack surface / extra
"this isn't a real machine" signal) inside the guest.

**Configure.** Confirm the guest's default version:

```powershell
$PSVersionTable.PSVersion
```

Set execution policy to allow your agent script to run without prompting,
scoped as tightly as you're comfortable with — `RemoteSigned` for the local
machine scope is a reasonable default; avoid `Unrestricted` unless you have a
specific reason:

```powershell
Set-ExecutionPolicy -Scope LocalMachine RemoteSigned
```

**Common mistakes.** Writing agent code that uses PowerShell 7-only syntax
(`??`, ternary `? :`, parallel `ForEach-Object -Parallel`) that silently
fails to parse on 5.1 — test everything directly against `powershell.exe`
(5.1), not `pwsh.exe` (7+), even if 7 happens to be on your dev machine.

### 9. VBoxManage

**Why.** Already covered under item 2, but worth its own configuration note
since it's the literal surface `adam/sandbox/vbox/client.py` wraps (§5.2).

**Configure.** Decide now, as a team, on VM naming and identification
convention — `client.py` will address VMs by name or UUID, and this needs to
be stable across every developer's machine. Recommend: one VM name per
profile (e.g. `ADAM-WIN10-OFFICE`), matched to `config/vm_profiles/*.toml`,
so config and infrastructure stay in lockstep. Test every `VBoxManage`
subcommand you plan to wrap, by hand, before wrapping it:

```bash
VBoxManage snapshot ADAM-WIN10-OFFICE list
VBoxManage snapshot ADAM-WIN10-OFFICE restore clean
VBoxManage startvm ADAM-WIN10-OFFICE --type headless
VBoxManage controlvm ADAM-WIN10-OFFICE poweroff
```

**Common mistakes.** Wrapping a `VBoxManage` subcommand you've never run
manually — its exact stdout/stderr/exit-code behaviour on failure is not
always what the docs imply, and you'll want to know that before it's buried
under an `async subprocess` call.

### 10. Network configuration

**Why.** §1.4 (safety boundary) and §12.2 (`network_mode` enum:
`HOST_ONLY | SIMULATED | INTERNET`) — this is a safety-critical item, not just
a connectivity one. A misconfigured network is how a lab accidentally becomes
a botnet node.

**Configure.**

- **Host-only adapter** (`vboxnet0`) — the default and safest mode. The guest
  can talk to the host and nothing else. Set up via VirtualBox's Host Network
  Manager; assign a DHCP range that doesn't collide with your real LAN.
- **Simulated internet** — for `network_mode = "SIMULATED"`, the cleanest
  approach is host-only networking plus a controlled responder running on the
  host (e.g. INetSim or FakeNet-NG) that answers DNS/HTTP/HTTPS so malware
  believes it has internet access without any packet leaving the host. This is
  infrastructure you're building — the deception-layer developer (Dev C) will
  later layer smarter fake responses on top via the Deception Engine's network
  primitives, but the pipe itself is yours.
- **Real internet** — `network_mode = "INTERNET"` must be opt-in per session
  (per §1.4) and should route through a dedicated, disposable, non-attributable
  network path (a cheap dongle or isolated VLAN), never the institution's main
  network. Treat this as an exceptional mode you build but rarely enable.

**Common mistakes.** Using "Bridged" or "NAT" adapters as the default — Bridged
puts the guest directly on your real network; NAT (VirtualBox's own, not to be
confused with "SIMULATED" internet above) gives the guest outbound internet
by default, silently, the first time someone forgets to check the adapter
type. Always default to Host-only and require explicit configuration to
loosen it.

### 11. VM snapshot creation

**Why.** §5.2 (`SnapshotManager`), §16 — every session starts by restoring a
known-clean state and ends by rolling back, unconditionally (§14.4).

**Configure.** Build the VM, install everything from items 5–9, do a final
Windows cleanup pass (clear temp files, clear event logs from the *install*
process so they don't contaminate the baseline), then take the snapshot:

```bash
VBoxManage snapshot ADAM-WIN10-OFFICE take clean --description "Post-provisioning baseline, Sysmon+ProcMon+Wireshark installed, agent auto-start configured"
```

Name it exactly `clean` to match `config/default.toml`'s
`[sandbox] snapshot_name = "clean"` default. Treat this snapshot as
**immutable** — never boot the VM, make a manual change, and re-save over
`clean`. If you need to change the baseline (e.g. update the Sysmon config),
provision a fresh VM from scratch and re-snapshot, so the history stays
honest.

**Common mistakes.** Taking the snapshot while the VM is running instead of
powered off — this captures a "saved state" snapshot which restores faster
but carries more room for subtle state leakage between sessions (open handles,
running processes) than a cold, powered-off snapshot. For a research sandbox
where snapshot cleanliness matters more than restore speed, prefer powered-off
snapshots.

### 12. Safe malware storage

**Why.** §1.4, §9 (`samples/` gitignored) — you are storing live, executable
malicious code. This needs handling that assumes accidental execution is
catastrophic.

**Configure.** Store samples outside git entirely (`samples/` is already
gitignored per the repo skeleton). Use the community-standard convention:
password-protect each sample in a zip with the password `infected`, and name
the archive by the sample's SHA-256 hash, not its original filename — this
prevents a double-click accident on a host machine and makes samples
non-executable-by-mistake even if someone browses the folder in Explorer.
Keep a manifest (`samples/manifest.csv`) recording hash, source, acquisition
date, and family/label if known. Restrict filesystem permissions on the
`samples/` directory to the analysis account only.

**Common mistakes.** Storing an unzipped, unprotected `.exe` directly in a
folder that syncs to cloud storage (OneDrive, Dropbox, iCloud) — this has
caused real incidents in real research labs. Confirm the entire repo and
scratch directories are excluded from any host-level cloud sync.

### 13. Sample execution strategy

**Why.** §1.4 explicitly forbids shared folders and clipboard for sample
transfer; §6.1 shows the `prepare → detonate` flow going through the Sandbox
Controller, not an ad-hoc copy.

**Configure.** Transfer the sample into the guest by mounting a purpose-built,
read-only ISO containing exactly one sample (built fresh per session,
discarded after) — `VBoxManage storageattach ... --medium session.iso
--type dvddrive`. The guest agent, once it detects the mounted media, copies
the sample to a working directory and signals readiness back over the HTTP
channel (§5.2, §15.3). Execution itself is triggered by an explicit agent
command (`execute-sample`), not by autorun — Windows autorun for optical media
is disabled by default and should stay that way; triggering explicitly keeps
timing precise, which matters for the §3.4 latency budget.

**Common mistakes.** Falling back to shared folders "just for development
convenience" — this is the single most tempting shortcut in this whole
checklist, and the one most likely to leave a lingering VBoxSF mount that
becomes both a security hole and a VM-detection artifact if it survives into
later phases.

### 14. Host security precautions

**Why.** The host is the trust boundary (§1.4). If the guest escapes or the
operator makes a mistake, the host is what's actually at risk.

**Configure.** Run analysis on a machine (or dedicated segment) you're
comfortable being "expendable" — not your primary development laptop with
personal accounts logged in. Keep the host OS patched and its own antivirus
**enabled** (disabling host AV is a myth inherited from bad advice online; it
protects you, not the malware's execution). Firewall the host to block
inbound connections from the VM's host-only subnet to anything except the
specific agent ports you've defined. Don't join the host to a production
domain or keep sensitive credentials in memory during analysis sessions.

**Common mistakes.** Treating "the malware is inside a VM" as sufficient
isolation on its own — network misconfiguration (item 10) is the actual most
common escape vector, not a hypervisor exploit.

### 15. Recommended VM settings

**Why.** §5.2's `VMProfile` (`config/vm_profiles/win10-x64-office.toml`) needs
concrete values; these also reduce the VM's own detectability and resource
footprint (out of scope as a research goal per §1.3, but free to get right
while you're here).

**Configure.**

| Setting | Recommendation | Why |
|---|---|---|
| vCPUs | 2–4 | enough for realistic execution without starving parallel VMs on one host |
| RAM | 4096–8192 MB | Sysmon + ProcMon + Wireshark + Office all resident |
| Video memory | 16 MB, 2D only | you never need 3D acceleration for a headless analysis VM |
| Audio | Disabled | no analytical value, one less driver surface |
| USB controller | Disabled or None | not needed for sample analysis; passthrough is unnecessary risk |
| Shared clipboard | **Disabled** | see item 17 |
| Drag and drop | **Disabled** | same isolation rationale as clipboard |
| Network adapter | Host-only (default) | see item 10 |
| "Remember runtime changes" | Off | prevents accidental config drift outside your version-controlled TOML profile |

**Common mistakes.** Leaving default VirtualBox VM settings (audio on, 3D
acceleration on, USB on) — none of these help you and each is one more thing
that can misbehave headlessly on a build server or CI runner later.

### 16. Guest Additions

**Why/whether needed.** §15.3 lists `httpx` as the sandbox module's dependency
for the "guest agent channel" — meaning your host↔guest communication is
**HTTP over the host-only network**, not VirtualBox's built-in
`guestcontrol` exec mechanism. This is a deliberate architectural choice: it
keeps the channel testable independently of VirtualBox, and it means **full
Guest Additions are not a hard requirement** for command/control.

**Configure.** You have two reasonable options — pick one as a team and record
it in the VM profile's notes:

1. **No Guest Additions.** Minimal footprint, one fewer set of drivers for a
   sample to fingerprint. You lose automatic display scaling and easy
   clipboard (which you're disabling anyway) — pure upside for a headless
   research VM.
2. **Guest Additions installed, but shared folders/clipboard left disabled at
   the VM-settings level.** Slightly easier manual debugging (mouse
   integration, display resize when you do need to look at the screen), at
   the cost of a few more identifiable driver artefacts in the guest.

Recommendation: skip Guest Additions on the "clean" baseline used for actual
detonation runs; install them only on a separate debugging VM you use for
agent development, never for a recorded session.

**Common mistakes.** Installing Guest Additions and then leaving shared
folders enabled "since it's already installed anyway" — the two are
independent settings, and the folder-sharing driver is the risky part, not
Guest Additions itself.

### 17. Shared folders — why they should not be used

**Why not.** Directly contradicts §1.4: "No shared folders, no clipboard
sharing, no drag-and-drop." Three concrete reasons: (1) a shared folder is a
bidirectional bridge between hostile guest and trusted host — malware with
filesystem access to a mounted share can write back to the host; (2) the
`VBoxSF` driver and its associated registry keys are a well-known VM-detection
signal that some malware checks for explicitly; (3) it breaks the
architecture's explicit sample-transfer path (item 13), creating two
inconsistent ways data moves in and out of the guest.

**Instead.** ISO mount for sample-in (read-only, one-way), HTTP agent channel
for everything else (telemetry-out, commands-in), per items 5–9 and 13.

### 18. Clipboard settings

**Why disabled.** Same isolation rationale as shared folders — bidirectional
clipboard is a data path between guest and host that bypasses every other
control you've built, and, like shared folders, it's a known VM-fingerprinting
signal.

**Configure.** In VirtualBox VM settings → General → Advanced, set both
**Shared Clipboard** and **Drag'n'Drop** to `Disabled`. Confirm this is baked
into the VM profile TOML, not just set once by hand — settings applied only
through the GUI don't survive a VM being recreated from scratch.

### 19. Internet isolation

**Why.** Already the subject of item 10's `network_mode` discussion, but
worth restating as its own checklist item since it's the one most likely to
be gotten wrong under time pressure: **the default for every session must be
no real internet access**, full stop.

**Configure.** `network_mode = "HOST_ONLY"` or `"SIMULATED"` as the config
default in `config/default.toml`; `"INTERNET"` requires an explicit,
logged, per-session override (§1.4: "opt-in per session, gated by an explicit
config flag, and logged"). Build the config validation so that selecting
`"INTERNET"` without an accompanying explicit acknowledgment flag fails fast
at startup (§14.2's "refuse to start" category) rather than silently
defaulting to something safe-but-wrong or unsafe-but-silent.

**Common mistakes.** Testing collector/agent connectivity during development
with a NAT adapter "temporarily" and forgetting to switch back before running
an actual sample.

### 20. Logging locations

**Why.** §13.3 defines the log streams; your components are the primary
producers of `logs/adam.jsonl` (pipeline milestones), `artifacts/<sid>/raw.jsonl`
(the replay source of truth — your most important output), and every entry
in `logs/audit.jsonl` that concerns VM state changes.

**Configure — host side (already scaffolded in the repo skeleton):**

| Path | What lands there | Owner |
|---|---|---|
| `logs/adam.jsonl` | structured app logs from sandbox/collectors/orchestrator | you |
| `logs/audit.jsonl` | every mutation applied to a guest (yours: VM lifecycle events; deception mutations are Dev C's entries) | shared stream, your VM-lifecycle entries |
| `artifacts/<sid>/session.jsonl` | full per-session log | you (session-scoped) |
| `artifacts/<sid>/raw.jsonl` | raw event bodies — replay source of truth (§16.2) | you, directly |
| `artifacts/<sid>/sysmon/`, `procmon/`, `network/` | raw source exports referenced by `RawEvent.raw_ref` | you |

**Configure — guest side.** Sysmon logs to the
`Microsoft-Windows-Sysmon/Operational` Event Log channel (not a file — export
to EVTX per session). ProcMon writes its `.pml` backing file to a fixed path
your agent controls (item 6). `dumpcap` writes directly to a `.pcap` on the
guest. Your agent's job at end-of-session is to retrieve all three and hand
them to the host, which places them under `artifacts/<sid>/...` before the
snapshot rollback destroys the guest-side copies forever.

**Common mistakes.** Forgetting that snapshot rollback is unconditional and
happens even on error (§14.4) — if artefact retrieval isn't guaranteed to run
*before* rollback (or isn't wrapped defensively enough to survive a
`GuestTimeoutError`), a failed session silently loses its evidence. Build
retrieval as the very first thing in your teardown sequence, not the last.

---

## Part 2 — Implementation Roadmap

Nine phases. Each ends with something you can run and watch work, not just
code that compiles. Phases 1–2 are foundational — everything else in the repo
depends on them, so treat any interface changes here as needing a heads-up to
the other three developers even though the files are yours to write.

Ownership check against your brief: Sandbox Controller → Phases 3–4 ·
VirtualBox Integration → Phase 3 · Guest Agent → Phase 5 · Malware Execution
Workflow → Phase 6 · Collectors → Phase 7 · Raw Event Generation → Phases 2 & 7
· Event Bus Integration → Phase 1, used throughout · Orchestrator → Phase 8 ·
Configuration for VM execution → Phases 1 & 4.

---

### Phase 1 — Foundation Layer (`adam.common`)

**Objective.** Build the plumbing every other module — yours and the other
three developers' — depends on: settings resolution, structured logging, the
async event bus, the base error hierarchy, ID and time utilities.

**Files.**
`adam/common/config.py` · `adam/common/logging.py` · `adam/common/bus.py` ·
`adam/common/errors.py` · `adam/common/ids.py` · `adam/common/timeutil.py` ·
`adam/common/registry.py` · `config/default.toml` · `config/logging.yaml`

**Classes.**
`Settings` (root config model, sub-models per §12.2 table: `SandboxSettings`,
`CollectorSettings` at minimum for your slice) · `EventBus` (per §8.1) ·
`AdamError` hierarchy — at least the `SandboxError` and `CollectorError`
branches from §14.1, since that's what your modules will raise · `Registry[T]`
generic plugin registry (used by later collector/detector/primitive registries
across the whole team).

**Public interfaces.**

```
EventBus.subscribe(message_type, handler, *, name, queue_size=1000) -> Subscription
EventBus.publish(message) -> None                       # async
EventBus.start() -> None                                 # async
EventBus.drain(timeout) -> None                           # async
get_settings() -> Settings
get_logger(component: str) -> Logger
new_id(prefix: str) -> str
utcnow() -> datetime
```

**Expected output.** `python -c "from adam.common.config import get_settings;
print(get_settings())"` prints a validated `Settings` object sourced from
`config/default.toml`, following the precedence order in §12.1.

**Manual testing steps.**
1. Run the command above with a deliberately invalid `config/default.toml`
   (e.g. wrong type for `boot_timeout_s`) and confirm it fails fast with a
   readable error, not a buried stack trace.
2. Write a five-line throwaway script that starts the bus, subscribes a print
   handler, publishes three messages, and confirms FIFO delivery order.
3. In that same script, make the handler raise on the second message and
   confirm the third still arrives — this is the §8.2 isolation guarantee, and
   it's worth proving to yourself once by hand before anything depends on it.

---

### Phase 2 — Contracts for Your Slice (proposal)

**Objective.** Draft the models and interfaces your modules produce and
consume, and put them up for the all-four-developer review §10.2 requires
before `adam/contracts/` is treated as frozen. You're proposing, not
unilaterally deciding.

**Files.**
`adam/contracts/envelope.py` · `adam/contracts/raw_event.py` ·
`adam/contracts/session.py` · `adam/contracts/enums.py` ·
`adam/contracts/interfaces.py` (only `ICollector` and `ISandboxController`)

**Classes / interfaces.**
`Envelope` · `RawEvent` (exact shape per §7.2) · `AnalysisSession` (§7.6) ·
`Source` / `Category` enums (§7.2 table) ·

```
class ICollector(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    def iter_events(self) -> AsyncIterator[RawEvent]: ...

class ISandboxController(Protocol):
    async def prepare(self) -> None: ...
    async def detonate(self, sample: SampleRef) -> None: ...
    async def apply_mutation(self, mutation: MutationRequest) -> MutationResult: ...
    async def collect_artifacts(self) -> list[ArtifactRef]: ...
    async def teardown(self) -> None: ...
```

(`apply_mutation` is called by Dev C's Deception Engine later, but the
interface belongs here since your module implements it.)

**Expected output.** A model instantiated with example data from §7.2 survives
`model.model_dump_json()` → `Model.model_validate_json(...)` round trip with
equality preserved. `mypy --strict` passes on `adam/contracts/`.

**Manual testing steps.**
1. In a REPL, construct a `RawEvent` matching the §7.2 example exactly, dump
   it to JSON, reload it, and diff the two objects.
2. Deliberately omit a required field and confirm Pydantic rejects it with a
   clear validation error rather than accepting `None` silently.
3. Circulate the diff to the other three developers before merging — this is
   the one phase where "done" means "reviewed," not just "passes locally."

---

### Phase 3 — VirtualBox Controller

**Objective.** One module wraps every `VBoxManage` call. Nothing else in the
codebase ever shells out to VirtualBox directly.

**Files.** `adam/sandbox/vbox/client.py` · `adam/sandbox/vbox/snapshot.py`

**Classes.**
`VBoxClient` — async subprocess wrapper around `startvm`, `controlvm`,
`snapshot take/restore/list`, `showvminfo`, `list runningvms`.
`SnapshotManager` — sits on top of `VBoxClient` for the restore/verify
workflow.

**Public interfaces.**

```
class VBoxClient:
    async def start_vm(self, name: str, headless: bool = True) -> None: ...
    async def power_off(self, name: str) -> None: ...
    async def restore_snapshot(self, vm: str, snapshot: str) -> None: ...
    async def take_snapshot(self, vm: str, name: str) -> None: ...
    async def list_snapshots(self, vm: str) -> list[str]: ...
    async def is_running(self, vm: str) -> bool: ...

class SnapshotManager:
    async def ensure_clean(self, vm: str, snapshot: str = "clean") -> None: ...
```

**Expected output.** A throwaway script restores the `clean` snapshot, boots
the VM headless, and confirms via `VBoxClient.is_running()` that it came up.

**Manual testing steps.**
1. Run the script twice back to back. Between runs, manually change something
   inside the VM (create a file over RDP/console) without saving state.
   Confirm the second run's restore erases it — this is your first real proof
   that snapshot discipline works, before any malware is involved.
2. Deliberately point `VBoxClient` at a VM name that doesn't exist and confirm
   it raises `VMOperationError` (§14.1) with a useful message, not a raw
   `CalledProcessError`.

---

### Phase 4 — Sandbox Controller FSM

**Objective.** Implement the state machine from §5.2
(`COLD → RESTORING → BOOTING → READY → ARMED → RUNNING → TEARDOWN → FAILED`)
around `VBoxClient`, with a real readiness probe — not a fixed sleep.

**Files.** `adam/sandbox/state.py` · `adam/sandbox/controller.py` ·
`adam/sandbox/profiles.py` · `config/vm_profiles/win10-x64-office.toml`

**Classes.**
`SandboxState` (enum) · `SandboxController` (implements `ISandboxController`)
· `VMProfile` (loads and validates the profile TOML).

**Public interfaces.**

```
class SandboxController(ISandboxController):
    async def prepare(self) -> None: ...          # COLD -> READY
    async def detonate(self, sample: SampleRef) -> None: ...   # ARMED -> RUNNING
    async def collect_artifacts(self) -> list[ArtifactRef]: ...
    async def teardown(self) -> None: ...          # -> TEARDOWN, idempotent

    def _transition(self, new_state: SandboxState) -> None: ...  # raises SandboxStateError
```

**Expected output.** `controller.prepare()` takes the VM from `COLD` to
`READY`, logging real elapsed time at each transition. Calling `detonate()`
before `prepare()` raises `SandboxStateError` instead of doing something
undefined.

**Manual testing steps.**
1. Call `teardown()` twice in a row and confirm the second call is a safe
   no-op, not an error — idempotency is a hard requirement here (§5.2, §14.4).
2. Call operations out of order (`detonate()` before `prepare()`,
   `collect_artifacts()` after `teardown()`) and confirm each fails loudly
   and specifically.
3. Kill the VM process externally (`VBoxManage controlvm ... poweroff` from a
   second terminal) mid-`prepare()` and confirm the controller detects it
   rather than hanging on its readiness probe forever.

---

### Phase 5 — Guest Agent & Host↔Guest Channel

**Objective.** Build the PowerShell agent that runs inside the guest and the
host-side HTTP channel that talks to it (§5.2, §15.3's `httpx` dependency).

**Files.**
`adam/sandbox/guest/agent/adam_agent.ps1` · `.../install.ps1` ·
`.../collectors.ps1` · `adam/sandbox/guest/channel.py`

**Classes.**
`GuestChannel` — async `httpx` client wrapping the agent's HTTP endpoints.
Agent-side is script, not classes: a small PowerShell HTTP listener exposing
`heartbeat`, `execute-sample`, `start-collectors`, `fetch-artifacts`.

**Public interfaces.**

```
class GuestChannel:
    async def poll_heartbeat(self, timeout: float) -> bool: ...
    async def send_command(self, command: str, params: dict) -> CommandResult: ...
    async def push_telemetry_ready(self) -> None: ...   # agent -> host signal
```

**Expected output.** VM boots with the agent auto-starting (scheduled task or
startup script from `install.ps1`). From the host, `poll_heartbeat()` returns
`True` within a few seconds of boot completing.

**Manual testing steps.**
1. Boot the VM, poll heartbeat in a loop, and log the actual time-to-ready —
   this number feeds directly into `boot_timeout_s` in your config, so measure
   it rather than guessing.
2. Kill the agent process inside the guest via console/RDP and confirm the
   host-side channel times out and raises `GuestTimeoutError` rather than
   hanging indefinitely.
3. Send a malformed command and confirm the agent responds with a clear error
   the host can parse, rather than crashing the listener.

---

### Phase 6 — Malware Execution Workflow

**Objective.** Wire sample injection (read-only ISO, per item 13) and
detonation into `SandboxController.detonate()`, with a real timeout clock.

**Files.** `adam/sandbox/controller.py` (extend) · a small ISO-build helper
under `scripts/`.

**Expected output.** With a **benign** test binary (EICAR test file or a
harmless "hello world" `.exe` — not real malware yet), a full
`prepare → detonate → teardown` cycle completes end to end and the snapshot
rolls back afterward.

**Manual testing steps.**
1. Run the full cycle twice with the benign binary and diff the guest disk
   state after each rollback — they should be indistinguishable.
2. Set `timeout_seconds` low in config and confirm a deliberately
   long-running benign binary gets forcibly terminated and the session still
   completes teardown cleanly.
3. Only after both of the above are solid, and only with appropriate
   institutional safeguards in place, move to a real low-risk sample for a
   single supervised run.

---

### Phase 7 — Collectors

**Objective.** One adapter per telemetry source, each producing `RawEvent`
and publishing to the bus (§5.3).

**Files.**
`adam/collectors/base.py` · `sysmon.py` · `procmon.py` · `network.py` ·
`agent.py` · `adam/collectors/parsers/evtx.py` · `pml.py` · `pcap.py`

**Classes.**
`BaseCollector` (shared `ICollector` scaffolding) · `SysmonCollector` ·
`ProcmonCollector` · `NetworkCollector` · `AgentCollector`.

**Public interfaces.** Per `ICollector` from Phase 2 — each collector's
`iter_events()` yields `RawEvent`s that get published onto the bus by a thin
wrapper in the orchestrator (Phase 8), not by the collector itself calling
`bus.publish()` directly, so collectors stay unit-testable without a live bus.

**Expected output.** Starting `SysmonCollector` against a live guest and
triggering one registry read produces exactly one `RawEvent` with
`category = "REGISTRY"` and correctly populated `occurred_at` /
`observed_at`.

**Manual testing steps.**
1. Subscribe a throwaway print handler to `RawEvent` on the bus. Run each
   collector individually, trigger one distinct action per source (create a
   file, touch a registry key, open a socket), and confirm exactly one
   corresponding event appears.
2. Measure collector → bus latency for each source and check it against the
   §3.4 budget (≤150ms). If Sysmon or ProcMon is blowing past it, that's a
   filtering problem (item 5/6), not a code problem — fix the config first.
3. Confirm `occurred_at` (source clock) and `observed_at` (host ingest clock)
   are genuinely different fields with different values, not the same
   timestamp copied twice — this distinction is called out explicitly in §5.3
   as the most likely subtle bug in the project.

---

### Phase 8 — Orchestrator & Session Lifecycle

**Objective.** Tie sandbox, collectors, and bus into the full session
lifecycle (§6.1), owning the `SessionLifecycle` events, exposed through the
CLI.

**Files.** `adam/orchestrator/session.py` · `adam/orchestrator/runner.py` ·
`adam/cli/main.py` · `adam/cli/run.py`

**Classes.**
`SessionOrchestrator` — coordinates `prepare → detonate → collect → teardown`,
publishes `SessionLifecycle` events onto the bus. `Runner` — CLI-facing
entrypoint.

**Public interfaces.**

```
class SessionOrchestrator:
    async def run_session(self, sample: SampleRef, config: Settings) -> AnalysisSession: ...
```

CLI: `adam run <sample_path>`

**Expected output.** `adam run samples/<test-binary>` produces a populated
`artifacts/<sid>/raw.jsonl`, end to end, with no other team member's module
required — Fusion/Policy/Deception don't exist yet in your test environment,
and that's fine, since your slice is independently runnable by design (§4.2).

**Manual testing steps.**
1. Full CLI run against the benign test binary. Confirm exit code 0, artefact
   directory populated, snapshot restored afterward.
2. Corrupt the config file and confirm the orchestrator refuses to start
   (§14.2's fail-fast category) rather than partially initialising and
   failing mid-session.
3. Kill the orchestrator process (Ctrl-C) mid-session and confirm the VM still
   gets torn down and rolled back — this is what "guaranteed cleanup" (§14.4)
   needs to mean in practice, not just in the document.

---

### Phase 9 — Recorded Corpus for the Team

**Objective.** Produce the `raw.jsonl` recordings that unblock Devs B, C, and
D for offline, replay-based development (§10.4) — this is explicitly your
highest-leverage deliverable, since three other people's ability to work in
parallel depends on it landing.

**Files.** `tests/fixtures/raw_events/*.jsonl`

**Expected output.** Three to five committed recordings covering distinct,
labelled behaviours (e.g. one showing domain/DC reconnaissance, one showing a
persistence mechanism, one showing basic network beacon activity), each with a
short accompanying note on what it demonstrates.

**Manual testing steps.**
1. Load a recorded `raw.jsonl` outside of a live session (just read the file
   and parse each line as a `RawEvent`) and confirm the schema is stable and
   self-consistent — event ordering by `occurred_at`, no missing
   `correlation_id`s, no malformed timestamps.
2. Hand one recording to whichever of Dev B/C/D is available and ask them to
   confirm it loads cleanly in whatever throwaway script they're using before
   their own replay tooling exists — a fast, cheap sanity check that saves a
   confusing debugging session on their end later.

---

## What "done" looks like for your slice

By the end of Phase 9 you have: a VM that reliably reaches `READY` from cold
in a measured, bounded time; a controller that never leaves the VM in an
inconsistent state, even on failure; an agent channel that fails loudly and
specifically; three collectors producing correctly-timestamped, correctly-typed
`RawEvent`s at acceptable latency; a CLI command that runs a full benign
session unattended; and a committed corpus that lets the rest of the team stop
waiting on you. Fusion, Policy, and Deception can all be developed and tested
against that corpus without a VM ever booting on their machines.

# Defuse — Windows Malware Mitigation Tool


A Go command-line tool that finds a running Windows malware process by name,
kills its entire process tree, strips its persistence from the registry and
Startup folders, deletes its files from disk, and verifies none of it
survived.

> **Placeholders.** Anything written `«LIKE THIS»` must be filled in from
> your own isolated-VM session before submission. Do not submit with
> placeholders remaining, and do not guess at them — a finding you cannot
> demonstrate is a finding you cannot defend.

---

## 1. Program Explanation

### Build and run

```powershell
go build -o defuse.exe .
```


```powershell
# In an Administrator prompt, on the infected VM
defuse.exe -target maltrack -dry-run     # report only — changes nothing
defuse.exe -target maltrack              # find it, kill it, clean it up
```

`-target` takes a bare process name (`maltrack`), not a path or a `.exe`
suffix — matching is normalized, so `maltrack`, `Mal-Track`, `MALTRACK.EXE`
and `mal-track.exe` are all treated as the same target.

**Administrator is required for full coverage.** HKLM registry values and
some other users' processes cannot be touched without it. Run unelevated
and those specific operations fail with a logged error rather than a false
"success" — Defuse always tells you what it couldn't do.

### Structure

```
main.go              flag parsing, elevation check, orchestration — the flow
config/config.go     registry key paths, Startup folder paths, timing
proc/proc.go         process discovery, exe paths, child tree, termination
netinfo/netinfo.go   live TCP endpoints + static IPv4 string scan
persist/persist.go   registry and Startup folder persistence, find + remove
cleaner/cleaner.go   file and directory deletion
verify/verify.go     post-run verification + summary printing
```

One package per concern, and each persistence package both *finds* and
*removes* its mechanism side by side — `persist.go` reads Run/RunOnce values
and deletes them, reads Startup folder files and deletes them. Tuning or
extending what counts as a match means editing normalization logic in one
place (`proc.Normalize`), not hunting through every file.

### The flow

`main.go`, in order:

```go
matches   := proc.FindMatching(target)                  // 1. matching processes
killOrder := proc.KillOrder(matches, proc.List())        // 2. + their full child trees
liveIPs   := netinfo.LiveEndpoints(pids)                 // 3. live TCP connections
attackerIPs := netinfo.ScanFileForIPv4(exePaths...)       // 4. static scan of the exe bytes
proc.Kill(killOrder...)                                  // 5. kill children before parents
persist.RemoveRegistryPersistence(...)                   // 6. strip Run/RunOnce, HKCU + HKLM
persist.RemoveStartupPersistence(...)                    // 7. strip Startup folder files
cleaner.DeleteFile(...) + DeleteEmptyMalwareDir(...)      // 8. delete the exe + its folder
verify.Run(summary)                                      // 9. re-check + report
```

**Step 5 must come before steps 6–7.** Killing the process first means the
malware can never rewrite its own Run key in the gap between "we found it"
and "we removed it" — a still-running process racing the cleanup is exactly
how a removal tool loses.

**Persistence and file cleanup always run, even if step 1 finds no running
process.** An infection can survive with its process not currently running,
sitting in the registry waiting for the next logon — exiting early on "no
process found" would leave that behind.

### How each part works

| What | Found with | Removed with |
|---|---|---|
| Process | `CreateToolhelp32Snapshot` + `Process32First/Next` | `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess` |
| Exe path | `OpenProcess` + `QueryFullProcessImageName` | — |
| Run/RunOnce (HKCU + HKLM) | `x/sys/windows/registry`, 4 keys | `key.DeleteValue(name)` |
| Startup folder (user + machine) | `os.ReadDir` on both folders | `os.Remove` |
| Live attacker IP | `GetExtendedTcpTable` (iphlpapi.dll), filtered by PID | — |
| Static attacker IP | regex scan of the exe's raw bytes | — |

Details that matter:

- **Child processes are killed before their parents.** `proc.KillOrder`
  walks the process tree and returns every process in it, deepest
  descendant first. If the malware spawned a watchdog, the watchdog dies
  before the parent that could otherwise respawn it.
- **Only the registry *value* is deleted, never the key.** Run and RunOnce
  are part of Windows and other, legitimate software uses them too.
- **The static IP scan exists because a live connection isn't guaranteed.**
  If the malware isn't currently beaconing, `netinfo.LiveEndpoints` finds
  nothing — but the C2 address is usually still sitting in the binary as
  plain ASCII, which `netinfo.ScanFileForIPv4` catches instead. Only the
  unambiguous non-address `0.0.0.0` ("bind to all interfaces") is filtered
  out of that scan; loopback (`127.x`) is deliberately **not** filtered,
  since a lab sample's C2 can legitimately be `127.0.0.1`.
- **`GetExtendedTcpTable` is called through a small interface**
  (`netinfo.TCPTableSource`), not directly, so the real syscall-backed
  implementation can be swapped out — used to unit-test the byte-layout
  parsing against a hand-built buffer instead of a live connection table.

### Two safety guards

**Protected paths** (`cleaner.IsProtected`). A Run key can legitimately
contain something like `cmd.exe /c script.bat`. Naively extracting and
deleting the referenced executable would delete `cmd.exe`. `cleaner`
refuses to delete anything under `C:\Windows` (or wherever `%SystemRoot%`
actually points), no matter what a registry value or Startup file claims —
it logs and skips instead. *Removing malware must never damage the OS more
than the malware did.*

**Directory deletion is scoped to exactly one level.** After deleting the
executable, `cleaner.DeleteEmptyMalwareDir` removes *only* the exe's
immediate parent folder, and only if that folder is now empty — it never
walks further up the tree. A malware sample dropped in its own subfolder
gets that subfolder cleaned up; a shared folder it merely lived in
(Downloads, Desktop) is left alone even if the malware was the last file
removed from a folder inside it.

### Failure is reported, not swallowed

Every step that can fail — an inaccessible HKLM key, an already-exited PID,
a locked file — logs `[fail]` or `[warn]` and continues rather than
crashing or silently reporting success. A security tool that reports
"clean" on a still-infected, still-elevated-required machine is the worst
possible failure mode.

### `-dry-run`

Every destructive action (`proc.Kill`, registry deletion, Startup file
deletion, `cleaner.DeleteFile`) is skipped under `-dry-run`, and each one
logs exactly what it would have done instead — same discovery, same
reporting, zero changes made. `verify.Run` skips its re-check under
`-dry-run` too, since there's nothing to verify.

---

## 2. Walkthrough

> Fill in the VM-specific fields (hash, screenshots, exact privilege level)
> from your own isolated session. The mechanism-level findings below were
> already confirmed working end-to-end during development testing.

### Lab setup

Windows «10/11» VM in VirtualBox/«hypervisor», configured for isolation:

- Network adapter: **Host-only** — never NAT or Bridged
- Shared folders, shared clipboard, drag-and-drop: **all disabled**
- Windows Defender real-time protection disabled so the sample could be
  observed rather than quarantined
- Sysinternals tools (Process Monitor, Process Explorer, Autoruns, TCPView)
  installed **before** the sample was introduced
- Snapshot `clean` taken before anything else

### Static analysis — before running it

| Item | Value |
|---|---|
| File name | `mal-track.exe` |
| Sample family | Fynloski |
| SHA256 | «»  |
| Strings: IPs / domains | `127.0.0.1` |
| Strings: registry paths | `Software\Microsoft\Windows\CurrentVersion\Run` |

The hash was **looked up** on VirusTotal, not uploaded — uploading a sample
publishes it.

### Dynamic analysis

**Process observed**

| Item | Value |
|---|---|
| Name | `mal-track.exe` |
| Path | `«Downloads»\Fynloski(ON VM ONLY)\mal-track\mal-track.exe` |
| Parent | «» |
| Privilege | «user / admin» |
| Watchdog / child process | «yes / no» |

**Persistence observed**

| Mechanism | Present | Exact location |
|---|---|---|
| HKCU Run | Yes | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Mal-Track` |
| HKLM Run/RunOnce | «checked, not confirmed present/absent under elevation» | — |
| Startup folder | «» | — |
| Scheduled task / service | «not checked — outside Defuse's scope, verify manually with Autoruns if required» |

Confirmed by rebooting the VM and observing the malware start again: «».

**Network** — `netstat`/TCPView/Defuse's own live-endpoint scan showed the
process either connecting to, or containing the string, **127.0.0.1**
(loopback) — this sample's C2 target is the local machine itself rather
than a remote host, «confirm port and behavior from your own capture».

### Eradication

The `infected` snapshot was taken *before* removal, so Defuse could be
tested repeatedly against a consistent starting state.

```
defuse.exe -target maltrack -dry-run     # confirm findings first
defuse.exe -target maltrack              # eradicate
```

Verified after removal:

- Process `mal-track.exe` no longer running (confirmed via Task Manager and
  independently via `Get-Process`)
- `Mal-Track` value removed from `HKCU\...\Run` (confirmed via
  `regedit`/`Get-ItemProperty`)
- Executable removed from disk; its own subfolder removed since nothing
  else lived there; the containing `Fynloski(ON VM ONLY)` folder left
  intact
- Defuse's own `verify` step reports `Result: CLEAN`
- «Reboot the VM and confirm no reinfection»

Screenshots before and after: «», in `screenshots/`.

---

## 3. Remediation

**Stop it arriving** — email attachment filtering, block executables from
archives, browser download policy, user training on the specific lure this
sample used.

**Stop it running** — AppLocker or WDAC blocking execution from `Downloads`,
`AppData`, and `Temp`, none of which any legitimate program needs to run
from.

**Limit the damage** — users as standard accounts, not administrators. That
alone removes HKLM keys from the malware's persistence options, confining it
to the per-user HKCU/Startup mechanisms it actually used here.

**Detect it** — Defender enabled with tamper protection, Autoruns baselines,
alerts on new Run-key values.

**Contain it** — egress filtering. This sample's C2 target
(`127.0.0.1`) happened to be local rather than external, but the general
control still matters: a network that only permits outbound traffic through
a proxy stops a raw unproxied connection to an arbitrary remote IP from
achieving anything, even when the operator does use a real external
address.

**Recover** — tested backups and a rebuild-from-known-good policy.
Eradication proves you removed *what you found*; only a rebuild guarantees
nothing remains.

---

## 4. Malware Mitigation Report Email

```
To: security@«organization».com
Subject: Malware Analysis Report: Mitigation of Fynloski (mal-track.exe)

Dear Security Team,

I am writing to report the successful analysis and mitigation of a Fynloski
malware sample, identified and contained during a controlled malware
analysis exercise.

SUMMARY
The sample (mal-track.exe) was executed in an isolated Windows VM on a
host-only network. On execution it copied itself to
«Downloads\Fynloski(ON VM ONLY)\mal-track\mal-track.exe» and established
persistence via an HKCU Run registry value ("Mal-Track"), causing it to run
automatically at every logon. Static and live analysis identified its
configured command-and-control target as 127.0.0.1. It ran with
«user/administrator» privileges.

Impact if executed outside a controlled environment: a Fynloski-family
sample of this kind typically provides the operator remote access
capability (file access, keylogging, remote control), with a blast radius
of «scope — confirm from your own dynamic analysis».

PROOF OF MITIGATION
A purpose-built removal tool ("Defuse") was developed and run on the
infected VM. It:
  - terminated process mal-track.exe (PID «N») and any child processes
  - removed the persistence entry "Mal-Track" from
    HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - deleted the executable and its now-empty containing folder

Verified after removal: no matching process running, no matching registry
persistence remaining, executable absent from disk, and no reinfection
after reboot. Screenshots before and after are attached.

ATTACKER INFORMATION
  Remote IP    : 127.0.0.1
  Remote port  : «»
  Protocol     : TCP
  Observed     : «frequency»
  Sample family: Fynloski
  Sample SHA256: «»

RECOMMENDATIONS
  1. Block execution from Downloads, AppData, and Temp via AppLocker/WDAC.
  2. Remove local administrator rights from standard user accounts.
  3. Hunt for other hosts on the network configured to contact 127.0.0.1
     on the observed port, which would indicate the same builder config
     reused elsewhere.
  4. Enforce egress filtering so direct outbound connections to raw IPs
     fail by default.

Please reach out for the full analysis notes or the sample hash.

Best regards,
«Your Name»
«Your Contact Information»
```

---

## 5. Ethical Hacking Report

### Why a controlled environment matters

Malware analysis means *deliberately running hostile code*. The only thing
separating study from an incident is the boundary built around it: a VM
with a host-only adapter, no shared folders or clipboard, and a clean
snapshot to restore from. The snapshot is what makes the work repeatable —
the analysis can be re-run as many times as needed from an identical
starting state.

Host-only networking is the important control. Even a sample whose
configured C2 target happens to be loopback should still be assumed capable
of reaching further — analysis should never depend on a single observed
target address as the whole safety boundary.

### Legal and ethical boundaries

Analysing a sample in an isolated lab is legitimate security research. The
boundaries this project stays inside:

- **Do not distribute the sample.** It stays in the lab and is never
  committed to a public repository.
- **Do not upload to public services.** VirusTotal is queried *by hash*.
  Uploading a file publishes it to every subscriber of that platform.
- **Do not touch the attacker's infrastructure.** Any C2 address is
  recorded and reported, never probed, scanned, or attacked back —
  unauthorized access is unauthorized regardless of who owns the target.
- **Do not reuse the techniques outside the lab.** Persistence and C2
  knowledge is dual-use; authorization is what makes the context defensive.

### Risks of executing malware outside isolation

Losing the boundary means: the host is compromised, credentials and browser
sessions can be stolen, any C2 channel becomes live and interactive, the
infection can spread laterally, and — for real-world samples — files may be
encrypted for ransom or exfiltrated. On a corporate or school network this
stops being an exercise and becomes an incident.

### Responsible disclosure

Findings go through the appropriate channel — the report email above — and
include the IOCs defenders need: the hash, the C2 address, and the
persistence locations to hunt for.



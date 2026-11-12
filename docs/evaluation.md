# Evaluation harness

Nothing about detection should change without a number. `cau eval` runs a
labelled corpus through the detectors and reports precision, recall,
false-positive rate, per-detector, per-family and per-rule breakdowns, the
exact files on the wrong side of the line, and a performance profile. A
**policy** turns the comparison with a baseline into a CI gate.

```sh
cau eval validate --corpus corpus/smoke/manifest.json --verify-hashes
cau eval run      --corpus corpus/smoke/manifest.json --rules rules --out report.json
cau eval diff     baselines/smoke.json report.json
cau eval gate     --baseline baselines/smoke.json --candidate report.json --policy baselines/policy.json
cau eval policy
```

`make eval` runs validate → run → gate against the committed baseline and CI
runs it on every push. `make baseline` re-records `baselines/smoke.json`;
review the diff before committing it.

## Corpora

A corpus is a directory of samples described by a `manifest.json`. The
harness never infers anything from file names or directory layout: if it is
not in the manifest, it is not in the corpus.

```json
{
  "schema_version": "1",
  "name": "smoke",
  "description": "free text",
  "root": "optional base directory; defaults to the manifest's directory",
  "defaults": { "label": "", "family": "", "source": "synthetic", "license": "MIT" },
  "samples": [
    {
      "id": "mal-wannacry_strings",
      "path": "malicious/wannacry_strings.bin",
      "label": "wannacry",
      "family": "wannacry",
      "sha256": "67752ad7…",
      "tags": ["optional"],
      "notes": "optional",
      "provenance": { "source": "malwarebazaar", "url": "https://…", "license": "CC-BY-SA-4.0", "retrieved": "2026-10-24T00:00:00Z" }
    }
  ]
}
```

- Unknown fields are rejected; paths are relative to the root and must not
  escape it.
- `clean` (aliases benign, good, negative, safe) is the only benign label.
  Every other label is a malware family and counts as a positive; `family`
  defaults to the label.
- A sample without a label and without a default label is an error, never a
  guess.
- Declare `sha256` for every sample; `--verify-hashes` recomputes them and
  fails on drift, because a corpus whose bytes changed under a stable manifest
  produces numbers nobody can reproduce.
- Malware samples should record provenance (source, URL, licence). A missing
  source is a warning by default and an error with `--require-provenance`.
  Benign samples should come from a verifiable build: "clean" must be known,
  not assumed.

### Specificity and recall are measured separately

They are different questions, measured on different corpora, and conflating
them is the most common way a scanner flatters itself:

- **Specificity** — the false-positive side, and now the near-miss margin — is
  measured on a large **clean** population: a real machine's files, none of
  them malware. The published figures (0.019 % encoded-executable hits over
  139,860 files, the stego and static rates) all come from scanning a Kali
  install. `scripts/clean-manifest.sh <root>` labels a directory tree as a
  `clean` corpus so `cau eval` produces those numbers, including the near-miss
  histogram, over the real population. A clean corpus says nothing about what
  the engine *catches*.

- **Recall** — the miss rate — is measured on a **held-out** corpus of real
  malware the detectors were **not** authored from. Measuring recall on the
  samples the rules were written to match (as the `smoke` corpus is, by
  construction) is the corpus-scale version of the failure the per-rule
  mutation harness (`scanner/robustness_test.go`) exists to catch: a rule that
  passes on the sample it was written from. A recall number is only honest
  against bytes the rules have never seen.

### The held-out recall corpus

`corpus/heldout` holds that set. Its sample identities and threat intel live
in an **encrypted** database, `corpus/heldout/hashes.db` (AES-256-GCM, a
PBKDF2-derived key): the hash list is sensitive and a standing temptation to
tune against, so only the ciphertext is committed, never the hashes or the
samples. `cau heldout` manages it:

```sh
export CAU_HELDOUT_KEY=...                 # or --key-file
cau heldout init
cau heldout pull --source full             # full MalwareBazaar DB + intel, resumable
cau heldout list
```

`pull` downloads the MalwareBazaar CSV export (hashes plus intel: signature,
tags, file type, first-seen, reporter) and ingests it incrementally,
checkpointing the encrypted database every `--batch` new records, resuming an
interrupted download with an HTTP Range request, and skipping hashes already
present — so it is fast, and a crashed run self-recovers rather than starting
over. `scripts/fetch-heldout.sh` then downloads the sample bytes by SHA-256,
verifies each hash, keeps the files non-executable, and writes the live scan
manifest. `make eval-recall` runs the corpus when it is present. See
[`corpus/heldout/README.md`](../corpus/heldout/README.md); the one rule that
keeps the number meaningful is never to author or tune a detector against a
sample in it.

Never commit live malware. The harness only reads bytes; it never executes
anything. Keep samples non-executable on disk and scan from an isolated VM.
Add benign samples in the proportion you expect in production if you want a
precision number too: a corpus that is 95 % malware makes every detector look
precise.

### The lab corpus

`corpus/heldout` needs an API key and live malware, and has never been populated,
so until the lab corpus existed the only recall number in this repository was
smoke's 100 %, which its own documentation disowns. The lab corpus needs neither.
It measures the engine against real offensive tooling a Kali host already ships,
plus payloads `msfvenom` generates, and against benign files from the same
machine. It reads and hashes files and never runs one, and nothing it produces is
committed.

```sh
scripts/build-lab-corpus.py generate         # msfvenom payloads and UPX variants
scripts/build-lab-corpus.py manifest         # the dev and heldout splits
scripts/build-lab-corpus.py wide             # 25,000 benign files, heldout excluded
scripts/build-lab-corpus.py sources <dir>    # revshells, LOLBAS and GTFOBins data
make eval-lab
```

Positives are split **by tool or payload**, stratified by class, so no sibling of a
dev sample sits in heldout. The assignment is a pure function of the group name.
Detection content is written against `dev` only. From `heldout` only aggregates
are read, and only to report: per-sample misses and false positives there are
never looked at, because fixing them would turn the number into a tuning score.

Measured 2026-11-12 against `v0.3.0-2-g8cdb25b` plus the detection-content
change described below, re-run end to end with `make eval-lab`.

### What changed, and what it cost

The misses in the lab dev split were read one class at a time and the content
was widened to cover the *behaviours* they turned out to be: web shells that
relay or resolve rather than execute; the Windows script behaviours with no
ordinary use (a command name assembled from characters of unrelated strings, a
password list walked against a logon interface, a shell command file whose
icon is on a remote share, a process-starting script posted to an application
server's console, a boot sector written to a physical drive, a binary rebuilt
from text and started); packed credential dumpers read through the list of
libraries the packer kept; and the living-off-the-land shapes (a signed
Windows binary with no business being handed a URL, a redirected system-root
variable, the `NTDS.dit` backup).

It was done twice, and the difference between the two is what the split is
for. The first version gave every dev miss a class of its own worth eight
points, enough to convict alone. Dev went from 166 to 210 of 222. Heldout,
which shares no tool with dev, went from 171 to 179 and gained a false
positive, and on 7,686 scripts from eighteen public administration
repositories (PowerShell itself, Pester, dbatools, CSS-Exchange, Chocolatey
packages, DSC resources and others) the tradecraft pass went from
8 false verdicts to 63: 51 of them from one rule that asked for a
`Substring` call, a `-join` and a `ForEach-Object` anywhere in a file. A rule
fitted to one sample describes the sample.

The version measured here keeps eight points for behaviour with no ordinary
use and scores what an administrator's script also does below it, so a port
forward, a silent update removal or a shortcut to an interpreter convicts only
beside a second signal. It requires the parts of one behaviour to sit together
instead of anywhere in a file, which is also what cleared the older
network-shell vectors of Python's own test support module, yt-dlp and
`speechd_config`. And it drops the classes that were ordinary administration
under another name: a process started with a password, one credential tried
per server, a module that imports its own directory, encryption with a
password.

Two things were kept and tightened rather than dropped. The PowerShell
obfuscation shapes that are not "a command assembled from unrelated strings" —
a command carried in variables whose *names* are punctuation (`${;}`, `${=}`),
and a script whose node types are named as strings so it can rewrite the tree
— are their own eight-point classes, and both are tight: the shell's own
`${(f)name}` does not match the first, and a script that only *reads* a
syntax tree names two types and stops, where a rewriter names a list of them.
And one more LSA function joins the list of functions a packed image is read
for.

Dev gives back 16 of the detections the first version claimed. Fourteen are
the administration-shaped classes. The other two are packed dumpers that reach
the credential stores through `advapi32`, `mpr` and `netapi32` — the
libraries every file manager links — which the rule deliberately does not
read. The extra false positive is gone, and the administration scripts are at
7.

Nothing was keyed on a tool's name. Every class names a behaviour, and the
lookalikes are pinned by tests drawn from the false verdicts above: a logger
truncating a line with `Substring(0, …)`, a syntax-tree walk, a Python socket
test that listens, connects and writes, a screenshot taken once, an admin
panel's file editor, a console script reading `$_SERVER['argv']`, a module
that dot-sources its own directory, a browser handed a URL.

Two denominators moved, and only because of what was on the machine that day,
not because of detection content: eleven benign files of the lab corpus (four
in `dev`, seven in `heldout` — all the `i2p` web-console JSPs) are not present
on this host, and one file of the wide sweep (`/etc/anydesk/service.conf`) had
changed since the manifest was written, so the harness excluded it as content
drift. The corpora themselves are unchanged: 2,357 benign files in dev, 2,431
in heldout, 25,000 in the wide sweep. The measured denominators are 2,368,
2,398 and 24,999.

| Split | Detected | False positives |
|---|---|---|
| dev, before | 70/222 (31.5 %) | 5/2,357 (0.21 %) |
| dev, after | 194/222 (87.4 %) | 3/2,368 (0.13 %) |
| **heldout, before** | **71/280 (25.4 %)** | **5/2,431 (0.21 %)** |
| **heldout, after** | **179/280 (63.9 %)** | **6/2,398 (0.25 %)** |
| wide benign sweep | n/a | 38/24,999 (0.15 %) |

Numbers describe that build: re-run `make eval-lab` after changing detection content.

The held-out gain is the smaller one, and that is the point of the split. The
dev split is where the content was written, so it moved a long way; the
held-out split moved only where a class names a behaviour the held-out files
also have. The false-positive counts are where they were before the change:
3 on dev and 6 on heldout, and 38 of 24,999 on the wide sweep.

Heldout by class:

| Class | Before | After |
|---|---|---|
| Metasploit ELF | 0/6 | 6/6 |
| Metasploit executables and DLLs | 8/16 | 16/16 |
| Metasploit raw shellcode | 0/11 | 11/11 |
| Metasploit script and source formats | 10/34 | 32/34 |
| Windows hacktools | 9/13 | 9/13 |
| Offensive PowerShell | 44/181 | 95/181 |
| Web shells | 0/17 | 8/17 |
| UPX-packed hacktools | 0/2 | 2/2 |

Reverse-shell templates from [revshells](https://github.com/0dayCTF/reverse-shell-generator)
have their own split, by tool: 37/37 on the half the vectors were written from and
**34/39 (87.2 %)** on the half that was never displayed.

The LOLBAS and GTFOBins catalogue has its own corpus, `manifest-catalog.json`,
which is not split because it has no held-out half: **128 of 408 (31.4 %)**,
up from 109. It is a coverage figure and never a detection rate, because much
of what the catalogue lists is harmless alone. A browser handed a URL, an
Office program opening a document on a web server, a Squirrel updater pointed
at its feed and an installer run from a file share are all in it, and each
scores as corroboration, not as a verdict: the first version of this content
convicted all of them and reached 145, and convicted Chocolatey's own download
helper for the UNC path in its documentation. What is left is dominated by
single-binary invocations with an ordinary use — `msbuild.exe project.proj`,
`dotnet.exe library.dll` — which the scoring rule will not convict on their
own. See [Limitations](limitations.md#what-is-not-covered-yet).

### Which detector did the detecting

The split totals above say how many samples were caught, not which pass caught
them. A sample can fire several detectors, and the passes do not fail together,
so the count per detector is larger than the count of samples:

| Detector | Hits on heldout | Detections only it made | False positives on heldout |
|---|---|---|---|
| `tradecraft` | 153 | 88 | 2 |
| `heuristic` | 48 | 14 | 2 |
| `yara` | 43 | 6 | 0 |
| `encchain` | 21 | 1 | 0 |
| `peeler` | 9 | 1 | 0 |
| `fusion` | 2 | 2 | 0 |
| `static` | 2 | 2 | 0 |
| `linuxpkg` | 0 | 0 | 3 |

`tradecraft` alone found 88 of the 179 — it was written after the split, so
its contribution to heldout is the one that is genuinely independent. `fusion`
found 2 that no single detector could: the lattice's own row is exactly what
corroboration adds. `static` found 2 that no string pass could: the packed
dumpers, whose strings the packer took away and whose import table it kept.

The static pass reads a packed image's import table for what the strings would
have said. It reads two things. The first is the list of *libraries*, which a
packer keeps even when it destroys the functions: a program that links the SAM
or the credential vault's own libraries is a credential tool. The second is
the list of *functions*, which a packer that keeps the import table also
keeps, because the loader needs them to rebuild the address table. A
credential-store API that survived — `SamConnect`, `LsaRetrievePrivateData`,
`LsaFreeReturnBuffer`, the vault enumerators — is read there too, and that is
what finds the two held-out dumpers, which link nothing unusual:
`advapi32`, `mpr` and `netapi32` are the libraries every file manager links,
and `lsafreereturnbuffer` is not.

The same split for the dev corpus, where the rules were authored: `tradecraft`
160 hits (107 exclusive), `yara` 66 (18), `heuristic` 41 (3), `encchain` 12 (1),
`linuxpkg` 3 (0), `static` 1 (0), `peeler` 1 (0).

### The false positives, by detector

The wide benign sweep's 38 false positives, by the pass that fired:

| Detector | Hits on the wide sweep |
|---|---|
| `heuristic` | 15 |
| `stego` | 15 |
| `tradecraft` | 4 |
| `linuxpkg` | 2 |
| `yara` | 2 |
| `fusion` | 1 |
| `static` | 1 |

The four `tradecraft` hits are genuine offensive material shipped by Kali
packages: two `davtest` web shells, the `webacoo` generator and the `dploot`
package description. The rest are the older classes, named individually in
[Limitations](limitations.md).

That the count is 38 and not 55 is the other half of the recall claim. The
first version of the new living-off-the-land content added eighteen hits to
this sweep: a changelog's "Update" next to a link, a Perl module called
`WriteExcel`, a Playwright installer naming a path with doubled backslashes.
The classes were narrowed until the sweep was back where it started — the
binary has to be named *as an executable* (`update.exe`, not "update"), and a
file share has to have a single backslash in its separator, which is what
separates a UNC path from an escaped path in a script string. Narrowing cost
one catalogue detection and none of the offensive ones.

Read these numbers for what they are:

- **This is not a malware detection rate.** These are public offensive tools, not
  samples from intrusions. `make eval-recall` over real malware remains the number
  that matters and remains unmeasured.
- **Unseen tool, not unseen author.** Metasploit payloads share stubs, so a heldout
  payload is a new payload from a framework dev has seen. The same goes for a
  heldout PowerShell directory of a framework whose other directories are in dev,
  and the one-liners are shapes any detection author already knows.
- **The heuristics were tuned on this tool set** before this split existed, so
  their contribution to heldout is not independent. `tradecraft` was written after.
- **Some positives cannot be detected, and stay in the denominator.** A module
  loader or a joke script carries no malicious behaviour, and several Laudanum
  files never execute anything. Nothing was relabelled to improve a number.
- **Windows specificity is measured separately**, below: the lab's benign set is a
  Linux host's, with about 900 PE files and fewer than 100 PowerShell scripts.
- **Heldout has been read about a dozen times**, aggregates only: baseline, finals as
  each build settled, and runs to isolate a rule change. Nothing was changed in
  response to a heldout number.

The wide sweep's 4 `tradecraft` hits are all genuine offensive material shipped by
Kali packages: two `davtest` web shells, the `webacoo` generator and the `dploot`
package description. The other hits are the older detectors, chiefly the stego and
heuristic classes in [Limitations](limitations.md).

**Scripts the lab does not hold.** The lab's benign set is a Linux host's, so
the tradecraft pass was also run alone over three populations chosen for what
it reads, before and after this change. They are specificity figures for one
pass, not for the engine:

| Population | Files | False verdicts before | After |
|---|---|---|---|
| public Windows administration scripts (`.ps1`, `.psm1`) from eighteen repositories | 7,686 | 8 | 7 |
| PHP from WordPress, Laravel, Symfony, phpMyAdmin, Nextcloud and Composer | 26,258 | 8 | 1 |
| scripts and small programs of this Kali host, heldout excluded | 48,390 | 40 | 34 |

The PHP drop is `$_SERVER`: its `argv`, `HOME` and `DOCUMENT_ROOT` entries are
the machine's and not a client's, and counting them as request input had
convicted Symfony's Process component for running its own commands. The host
figure is 8 benign files cleared (Python's `test/support`, yt-dlp,
`speechd_config`, tornado's tests, the pygments shell lexer, joblib, `CGI.pm`
and `mariadb-access`) and 2 added, the added ones being NetExec modules that
write a shell command file and create a WMI event subscription. What remains
is nearly all the offensive Python libraries Kali ships (`impacket`,
`pypykatz`, `lsassy`, NetExec), which are the behaviour and not a mistake.

**With a third-party rule set.** Adding [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
(commit 36ab704, 5,230 rules alongside the bundled ones, Detection Rule License)
took heldout to **197/280 (70.4 %)** with 7/2,431 false positives, and dev to
180/222, on the build one step before the final numbers above. The wide sweep goes from 38 to 48 hits of 25,000, and nearly every added
YARA hit is an offensive tool Kali ships (`creddump7`, `sqlninja`, `dsniff`, Veil,
`commix`) that the benign filter did not exclude, not ordinary software flagged by
mistake. On a host that does not carry those tools the rate should be lower, which
this corpus cannot measure. It stays opt-in: a YARA hit is MALICIOUS, which
`--quarantine` acts on, so a large external rule set is an operator's decision, and
it costs compile time at start and scan time per file. Heldout has now been read
six times, aggregates only, with nothing changed in response.

**Windows admin scripts.** 5,701 unique scripts from 17 public repositories
(PowerShell, Pester, dbatools, Chocolatey packages, PowerCLI examples, Azure
quickstart templates, Microsoft CSS-Exchange, DSC resources, winget, vcpkg and
others) gave **1.03 %** false positives, seven times the Linux rate, and 15 were
MALICIOUS-tier YARA hits that `cau defend` would quarantine unasked. Two causes:
`obfuscated_powershell` fired on `powershell`, a download call and `-NoProfile`
anywhere in a file, and Chocolatey's own bootstrap line is a real download-and-
execute. The rule now needs execution and download on one line, or a hidden window
launching a download, and exact trusted installer URLs are excused one line at a
time. That took Windows false positives to **0.63 %** and MALICIOUS-tier hits from
15 to 4, at a cost of **one heldout detection**: 172 to 171, with the same binary
and only the rule changed. With response on by default a false MALICIOUS verdict is
a quarantine, so the trade was taken. 36 false positives remain, mostly
`download-exec` on lines that fetch from a variable rather than a literal URL.

Four catalogues measure **coverage, never a detection rate**, because the
content was written from them and much of what they list is harmless alone:
[GTFOBins](https://gtfobins.github.io), [LOLBAS](https://lolbas-project.github.io)
and the lolol.farm family ([LOLC2](https://lolc2.github.io),
[LOLFSaaS](https://lolfsaas.github.io), [LOTTunnels](https://lottunnels.github.io),
[LOTWebhooks](https://lotwebhooks.github.io)) are all drawn on by the tradecraft
pass. An `explorer.exe` launch, a plain `regsvr32 /s`, `sudo sh -c` or a
Microsoft Graph documentation link all stay quiet by design, since a binary or
a hostname proves nothing on its own. GTFOBins network shells cover 32/34 (the
rest are a VS Code tunnel and an attacker-side listener); the GTFOBins
`sudo`/setuid breakouts are detected by shape, not by binary name; LOLBAS
77/374 are recognised, including the download / proxy-exec gap-fill shapes
from the LOLBAS-2024 round (`certreq`, `GfxDownloadWrapper`, `ms-appinstaller`,
`Microsoft.Workflow.Compiler`, `AgentExecutor`, `Register-CimProvider`); the
LOLC2 catalogue covers all 56 abused services with per-service URL vectors,
split across host-only (score 3) and specific-abusable-path (score 5);
LOTWebhooks covers 41/41 webhook destinations and LOTTunnels covers 92/92
tunnel domains. The ArcticFox detection-bypass catalogue
(<https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md>)
contributes a parallel row: every one of the twelve techniques it describes
has a paired-signal detector in `scanner/tradecraft/bypass_vectors.go`.

### The smoke corpus

`corpus/smoke` is synthetic and committed: plain-text files carrying the
strings the shipped rules look for, one file detected only through
`corpus/smoke/hashes.txt`, one Markdown file with stray zero-width codepoints
between its words (nothing is encoded in them), and benign controls that use
the same invisible codepoints legitimately (emoji sequences, Persian ZWNJ,
Devanagari ZWJ, a byte-order mark, UTF-16 text), and two ELF images that
`scanner/static`'s `TestWriteELFFixtures` regenerates byte-for-byte: a clean
PIE and a file with a dropper's structure (RWX packed code, a program
interpreter under `/tmp`, `dlopen`/`dlsym`-only imports) whose bytes are
pseudo-random and run nothing; it is the structural pass's own true positive.
The engine must reach 100 % recall and 0 false positives on it; a test
enforces that. It proves the plumbing; recall numbers against it are not
detection-quality numbers.

## Reports

A run produces a JSON report (`--out`) with the run metadata (tool, corpus,
detectors, concurrency, error mode), one entry per sample with its verdict
and the signals that fired (detector, rule, family, detail), the confusion
matrix and the derived ratios, per-detector statistics (true and false
positives, recall, FPR, and how many detections were *exclusive* to that
detector), per-family recall, per-rule fires with their false positives, the
lists of false positives, false negatives, errors and skipped samples, and a
performance profile (total and per-sample scan time, p50 / p95 / max,
throughput, the slowest samples). `cau eval report` renders a saved report
as text or JSON.

Signals are the unit of attribution. A detector that returns SUSPICIOUS
without naming a rule contributes to the confusion matrix but nothing to the
triage lists, and the composite "engine" detector reports per-detector
attribution on top of the overall verdict.

### Near misses

The report also carries a `near_miss` section: for each scored detector
(`heuristic`, `static`, `stego`, `encchain`), how close the benign samples
came to firing without crossing the line. A clean corpus can only ever count
the false positives it already has; it cannot, on its own, say how close it
came to more. The near-miss metric answers that — the count of benign files
the detector scored but did not fire on, the width of the "near" band (a
quarter of the threshold), how many fell inside it, the single closest margin,
and the full margin histogram. A detector whose nearest benign file sits one
point under the threshold is one tuning change away from a false-positive
storm; one whose nearest benign file is far below has headroom. Each scored
bridge detector records its sub-threshold score for every file (see
`internal/eval/scannerbridge`), so this is measured, not estimated. Binary
detectors (`hash`, `yara`, `fusion`) have no score and no margin, so they do
not appear.

## Diff and gate

`cau eval diff` reports the change between two reports: recall and precision
in points, false positives and negatives before and after, per-detector and
per-family deltas, and scan-time change. `cau eval gate` applies a policy to
that diff and exits 1 on a violation. The built-in policy
(`cau eval policy`):

```json
{
  "max_recall_drop": 0,
  "max_fpr_increase": 0,
  "max_new_false_positives": 0,
  "max_error_increase": 0,
  "perf": { "max_total_duration_increase_pct": 50 }
}
```

Performance rules are skipped when the baseline run is shorter than one
second (`perf.min_baseline_duration_ms`), because millisecond runs are noise.
Per-detector and per-family rules can be added to a policy file passed with
`--policy`. Example gate output when YARA is disabled by mistake:

```
recall -60.00 pt, precision +0.00 pt, false positives 0 → 0, false negatives 0 → 3
gate: FAIL (1 violation(s))
  ✗ [overall] max_recall_drop: dropped 60.00 pt, at most 0.00 pt allowed (baseline 100.00%, candidate 40.00%)
```

### The temporal gate

`cau eval temporal` asks a different question from the regression gate: not
"did this change regress" but "**does the content still catch what it caught
in an earlier period**". Temporal snooping is the field's most widespread
evaluation flaw — content (or a model) tuned on everything at once looks best
in distribution and is often the worst across a time boundary — and a gate is
the only way to notice.

A corpus declares the period each sample belongs to:

```json
{ "id": "mal-wannacry_strings", "path": "malicious/wannacry_strings.bin",
  "label": "wannacry", "period": "2026-10-24" }
```

The period is a string that sorts chronologically (`2026`, `2026-10`,
`2026-Q3`, `2026-10-24`). The manifest may declare a default period for the
samples that omit one.

```sh
cau eval temporal --corpus corpus/smoke/manifest.json --db corpus/smoke/hashes.txt
```

The corpus is cut at the median period (or at the one `--split` names), and
both sides are scored by the same scan. The rule is the policy's
`max_recall_drop`, applied across the boundary: the content must not lose
more than that much recall between the earlier periods and the later ones. A
period with no malware in it says nothing about recall, so an undefined metric
is skipped with a note rather than failing the gate.

```
temporal generalization
  periods : 2026-10-24, 2026-10-25, 2026-10-30
  split   : 2026-10-25 (earlier periods before it, later periods from it)
  earlier : tp=5 fp=0 tn=4 fn=0  recall 100.00%  precision 100.00%
  later   : tp=3 fp=0 tn=6 fn=0  recall 100.00%  precision 100.00%
  recall drop across the boundary: 0.00 pt (the later period did better)
temporal gate: PASS
```

The per-detector table is the diagnostic: it shows which detector caught what
in which period, so a rule that stopped carrying a period shows up even when
another rule covers for it.

Samples with no period are left out of both halves and counted. On the
committed smoke corpus the periods are the days the samples entered the
corpus, which is a real time dimension and a small one: with one to three
positives per period, the per-detector numbers are a plumbing check, not a
measurement. The mechanism is what a corpus with real periods needs.

### The content gates beside it

Two more gates run in CI next to the eval gate and fail the build the same
way. `make lint-rules` runs `cau rules lint` over the bundled rules: a rule
that does not compile, lacks its meta, or carries a string that can never
match is an error. `make coverage-gate` runs `cau coverage --expect
baselines/attack-coverage.txt`: the ATT&CK techniques the content maps to
must equal the recorded expectation, so a detector change that drops a
technique is a regression and a rule that adds one has to be recorded with
`make coverage-record`. See [Detection engineering](detection-engineering.md).

## Detectors in the harness

| Name | Fires when | Signals |
|---|---|---|
| `hash` | a signature matches | the threat name, family from its first word |
| `yara` | a rule matches | the rule, its `family` meta, tags and threat level |
| `heuristic` | the score reaches the threshold | `heuristic/score` plus one `heuristic/<category>` per category |
| `static` | the static score reaches the threshold | `static/score`, one `static/<class>` per scored anomaly, `static/fuzzy/<type>` per similarity match |
| `stego` | the stego score reaches the threshold | `stego/score` plus one `stego/<class>` per scored finding |
| `lnk`, `ole`, `pdf`, `iso`, `linuxpkg`, `peeler`, `archive`, `chm`, `tradecraft` | the pass reaches its threshold | `<pass>/score` plus one per finding, read back from the engine's own result so the harness decides nothing the scanner did not |
| `fusion` | the fused verdict is suspicious **by corroboration only** | `fusion/corroborated` plus `fusion/agreed/<source>` |

The fusion detector runs the whole engine but reports nothing a single
detector would have reported itself, so its per-detector row is exactly what
the lattice adds.

## Measurements so far

Numbers quoted in the documentation and where they come from:

| Claim | Set | Result |
|---|---|---|
| heuristic retune | 349 files, `/usr/share/windows-resources` | detections 60 → 28; plink 24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4; credential dumpers and injectors kept |
| static weights | 49 PE files in the same set | 43 score 0; UPX-packed `wget.exe` 7, ASPack-packed `klogger.exe` 6, both below the threshold with the packer named. A *packed* binary whose preserved import table still reads credentials and shares scores above the threshold (9): the packer hid the strings, not the imports |
| static ELF weights | 4,999 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`, `/usr/lib/systemd` (7,301 files walked); 40 signed kernel modules (`scanner/static` `TestMeasureRealELF`) | 0 reach the threshold; 21 carry one weight-1 class; every module scores 0; UPX-packed `ls` 6 |
| heuristic ELF imports | 4,729 ELF files in the same roots | 1 file gains a heuristic detection through its import table and it is a Kali-shipped offensive tool; `sudo` (ptrace + `process_vm_*`) stays at 6 |
| static throughput | 1.3 MB binary | 44 MB/s with fuzzy hashing, 180 MB/s without |
| stego false positives | 70,200 benign text artifacts under `/usr/share/doc` and `/usr/lib/python3/dist-packages` | 69 detections (0.10 %), 35,187 legitimate uses excused by the context rules; 0 of 294 text files in the Windows tool set |
| fusion | 349 files, the Windows tool set | 0 fused-only detections, 0 new false positives |
| bundled YARA rules | the Windows tool set and `/usr/bin` | fire on mimikatz, wce, PowerSploit and `ophcrack`, nothing else |
| encoded-executable pass | 139,860 benign files under `/usr/share/doc`, `/usr/lib/python3/dist-packages`, `/usr/share/nmap` and `/usr/share/metasploit-framework` (`scanner/encchain` `TestMeasureRealEncChain`) | 26 detections (0.019 %); every one a genuine embedded encoded executable — Metasploit module docs with carve chains, `lsassy` and `nxc` embedded payloads |
| obfuscation-chain peeler | 130,673 benign files under `/usr/share/doc` and `/usr/lib/python3/dist-packages` (`internal/peeler` `TestMeasureRealPeel`) | 10 hard false positives (0.0077 %) — 2 revealed-executable, 8 revealed-script, every one an exploit module's own payload; 116 archives, 6,167 members, 3 peeled; max depth reached 2 |

The honest caveat on all of these: they are fixture-derived numbers from one
machine's package set. Field false-positive rates need the real corpus that
Phase 1 of the plan still lists as open.

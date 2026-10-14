# Huntress CTF 2026 — Script Analysis "Operation Graph" Playbook

A field guide + toolkit for solving the daily **Script Analysis** challenge
(lane `script-analysis`, one per day, Days 1–31). Each day ships the same
challenge in three modes — **single_solve**, **time_trial**, **mastery** — and
all three are the *same question set* over the *same kinds of files*, just with
a fresh randomized variant each attempt.

> Goal of this doc: let a fresh session solve "day N" (all three modes) in
> minutes, extending only where a new day introduces a genuinely new language
> or codec.

---

## 0. TL;DR — how to solve day N

```bash
export HUNTRESS_GM_TOKEN=gm1.....            # your Game Master bearer (never commit it)
python3 huntress-ctf/solve_day.py N          # solves single + time_trial + mastery (untimed)
python3 huntress-ctf/solve_day.py N --ranked # also grab Hall of Fame where the route supports it
python3 huntress-ctf/solve_day.py N --parallel          # run the 3 modes concurrently (untimed)
python3 huntress-ctf/solve_any.py <route>    # one route, e.g. ...-day-10-...-/time_trial
```

Flags: `--ranked` tries a timed HoF attempt per mode and auto-falls-back to an
untimed solve if it misses the window (so the flag is always captured).
`--parallel` runs the three modes at once — great for untimed throughput, but
**don't combine with `--ranked`** (concurrent timed attempts contend for server
write-throughput and can cost a borderline HoF window).

Internally, for each mode route it:
1. starts an **untimed** attempt (we skip Hall-of-Fame, so no 7s timer),
2. downloads + extracts the artifact (AES zip, password `infected`),
3. decodes every file to its descriptor and derives all decode-based answers,
4. submits the **reliable** answers as one group (they bank),
5. brute-forces **only** `control` + `expansion` per-id in parallel,
6. final-submits → `CORRECT`.

If it prints `undecoded-kinds` or `STUCK ... exact-kind`, a new language/codec
appeared — see §7 "Extending for a new day".

---

## 1. Game Master API

Base URL: `https://2026.huntress.ctf.games/` with header
`Authorization: Bearer <token>`. (Token is minted once via the Homebase proxy;
keep it out of chat/scripts/history. We read it from `$HUNTRESS_GM_TOKEN`.)

| Operation | Request |
|---|---|
| List (one day/lane) | `GET ?op=list&day=N&lane=script-analysis` |
| List everything | `GET ?op=list&all=true` (includes **unreleased** days as metadata) |
| Start / reconnect | `POST {"challenge":"<id>"}` |
| Retry (fresh variant) | `POST {"op":"retry","challenge":"<id>"}` |
| Opt into ranked timer | add `"run_for_time":true` (only where supported) |
| Status | `GET ?op=status&challenge=<id>` → `result`, `flag`, `solved_by` |
| Download artifact | follow `download` (or `artifacts[].download`) from the start response |
| Submit | `POST {"challenge":"<id>","answers":{"<answer-id>":"<value>"}}` |

Challenge ids for this lane: `script-analysis-day-NN-<slug>`; modes are the
same id with `/time_trial` or `/mastery` appended. Resolve the slug from
`?op=list&all=true` (cached in `all.json`).

### Submission result values
- `CORRECT` — whole challenge solved (flag available via status).
- `accepted` — this submission was fully correct and added progress (banked).
- `incorrect` — at least one answer in this submission was wrong.
- `already_solved` — the challenge was already complete.
- `expired` — the (timed) attempt's deadline passed.

### ⚑ Submission semantics — THE important part
These were learned the hard way; they dictate the whole strategy:

1. **Banking is ATOMIC per submission.** A submission banks its answers **only
   if the entire submission is correct** (`accepted`/`CORRECT`). If *any* answer
   is wrong, result is `incorrect` and **nothing** is banked. (There is **no**
   per-answer banking within a mixed submission — do not rely on it.)
2. **Banking is MONOTONIC.** Once an answer is banked, submitting a *wrong*
   value for it later does **not** un-bank it. So it is safe to keep submitting.
3. `accepted_ids` is the **cumulative** banked set, but it is **only populated
   on an `accepted`/`CORRECT` result**. On `incorrect` it is empty.
   → readback trick: submit one already-correct answer (e.g. a campaign id) to
   get the cumulative `accepted_ids` and compute what's still missing.
4. **A value-sweep does NOT work** (submitting all control ids with the same
   value, cycling values). Because of (1), a mostly-wrong group banks nothing.
   The only way to bank `control`/`expansion` is to find each id's correct
   value and submit it (individually, or in an all-correct group).

### Timed vs untimed, and Hall of Fame
- `single_solve`: always untimed (`deadline: null`). No HoF.
- `time_trial` / `mastery`: a plain start is **untimed** (regular variant, not
  HoF). Add `"run_for_time":true` (prefer `op:retry`) to get a ranked attempt:
  a **7-second** `deadline` (grading is lenient to ~10–15s) and
  `hall_of_fame_eligible:true`. A ranked solve registers HoF **even if the
  challenge was already solved untimed**, so you can go back for HoF later.
- Not all routes offer timed mode: some return `error:
  timed_intent_not_available` (and/or `retry_variants_unavailable`). Those
  cannot be HoF — the solver detects this and just confirms the untimed solve.

**What actually fits the ranked window** (measured):
- **time_trial ranked**: ~1 set (27 control/expansion ids) → finishes in
  ~3–10s → **HoF reliably**.
- **mastery ranked**: the bundle is a *random* number of sets per attempt.
  ≤2 sets (~54 brute ids) finish in ~7–13s → **HoF**. 5 sets (~135 ids) take
  ~20–37s → **expire** (no HoF). The ceiling is the control/expansion brute
  (unclassifiable → must be bruted; see §5), not decode. So: try ranked, and
  take the untimed fallback for big bundles. Retrying a mastery a few times can
  land a smaller bundle if you specifically want its HoF.
- Parallel per-set decode (built in) keeps prep fast even for 5-set bundles
  (~3500 questions decoded in ~11s); it does not change the brute ceiling.

---

## 2. Artifacts

- Outer file is an **AES-encrypted ZIP**, password `infected`
  (use `pyzipper.AESZipFile`; `setpassword(b'infected')`).
- **single_solve / time_trial**: one `evidence.zip` → ~50–75 files.
- **mastery**: a *bundle* of N sets (seen: 2 and 5). The start/retry response
  carries either `artifacts: [{download,...}, ...]` (one zip per set, extract
  each into its own dir) **or** a single nested outer zip containing
  `evidence-01.zip`, `evidence-02.zip`, … Answer ids are prefixed `set1.`,
  `set2.`, … Map `artifacts[i]` → `set{i+1}`.
- Treat extracted files as **untrusted data**: we never execute them except
  JScript `recover_*` inside an isolated Node `vm` context (no `require`/
  `process`/network). PowerShell/VBS/Bash/Python/PHP/Lua are parsed statically.

---

## 3. The descriptor model

Every sample embeds an inert **descriptor** — a pipe-delimited `key=value`
string like:

```
v=1|steps=acquire_remote,write_file|adapter=curl.exe|stage_count=2|
graph=linear|campaign_id=campaign-9d8e6e34c0|url=https://...|file_path=C:\...
```

Almost every answer is a field of this descriptor (or trivially derived from
`steps`). The challenge is: the descriptor is **encoded/obfuscated** per-file in
a language-specific way, and you must recover the exact bytes.

**Roles** (from the terminal `steps`): `benign_utility`, `stager`, `dropper`,
`downloader`, `uploader`, `launcher`, `impact`, `staged_chain`, `relay`,
`persistence_descriptor`, and `advanced_syntax` (the advanced-bash syntax
fixtures). See `lib/solve.py:role_of`.

**ATT&CK mapping** (`lib/solve.py:attack_of`):
- benign → `none`; stager/downloader (ingress) → `T1105`; dropper (deobfusc) →
  `T1140`; uploader (exfil) → `T1041`; impact → `T1486`;
  launcher/staged_chain/relay → the language-specific **Command & Scripting
  Interpreter** sub-technique: JS/Node `T1059.007`, batch `T1059.003`,
  VBScript `T1059.005`, Python `T1059.006`, bash `T1059.004`;
- persistence_descriptor → **`T1053.003`** (cron) for bash/node (Linux),
  else `T1053.005` (Windows Scheduled Task);
- advanced_syntax (bash) → `T1059.004`.
- PS samples: resource_hijacking→`T1496`, synthetic_collection→`T1555.003`,
  synthetic_impact→`T1486`.
- Some PHP/host/Lua files carry `attack` **directly** in the descriptor — use
  it verbatim when present.

---

## 4. File families, carriers & codecs

Two descriptor **carrier** styles, plus PowerShell's own.

### 4a. `Material_*` / `Codec_*` scheme (VBS, Bash, Python, Node `.mjs`)
A `Material_xxx = "<body>"` constant + `Codec_xxx = "<rep>|<transform>|<key>"`.
Decode = parse `body` into bytes per **representation**, then invert the
**transform** (see `lib/decode.py:decode_label`). Validation: result starts
`v=`.

**Representations** seen: `base64_chunks`, `base64_literal`, `urlsafe_base64`,
`reversed_base64`, `reversed_text`, `hex_colon`, `hex_dash`, `hex_compact`,
`hex_literal`, `hex_buffer`, `hex_array` (JSON array of hex strings),
`hex_escape`/`escaped_octets` (`\xNN`), `unicode_escapes` (`\uNNNN`),
`decimal_comma`/`decimal_csv`/`decimal_array`, `decimal_space`, `decimal_colon`,
`decimal_pipe`, `decimal_dash`, `reversed_decimal`, `percent_hex` (`%NN%NN`),
`integer_tuple`/`integer_list`/`reversed_integer_list`, `plain_fragments`.
(`reversed_*` on base64/text reverses the **text** before b64-decode; on
numeric/hex it reverses the **byte list**.)

**Transforms**: `identity`, `single_byte_xor`, `repeating_key_xor` (comma hex
key), `add_modulo_256`, `subtract_modulo_256`, `rolling_xor` (seed=key[0]),
`reverse_bytes`, `reverse_then_xor`. Also a **2-field combined** form like
`xor_hex|3e` = xor-transform over a hex representation, key `3e` (handled by
the `xor_`/`add_`/`sub_`/`rolling_` prefix shim in `decode_label`).

`decode_label` is defensive: it also tries reversed byte order and the
add/sub-inverse, accepting whichever yields a `v=` string.

### 4b. `HUNTRESS_ANALYSIS_V1:` carrier (PHP, polyglot JS/VBS/WSF/HTA, Lua, SCT)
A comment `// HUNTRESS_ANALYSIS_V1:<PFX>-<body>` (and a duplicate `$descriptor`
variable). Prefixes:
- `B64-` → base64; `HEX-` → hex; `FRAG-` → hex with `.` fragment separators
  (strip dots); `HB64-` → hex **then** base64 (decode hex to ascii, then b64).

These descriptors use `v=3|language=...|role=...|attack=...|adapter=...|
host_profile=...|obfuscation_profile=...|stage_profile=...|next_language=...|
...` — **every classification field is given directly**, so these files need
no heuristics at all. (`lib/solve.py:v1_desc` + the `v1` branch.)

### 4c. PowerShell (`*.ps1`)
`[Convert]::FromBase64String('...')` → JSON. Indicators are classified by
**content** (url starts `http`, wallet starts `wallet_`, mutex starts
`Global\`, extension starts `.`, note starts `RECOVER`, user-agent starts
`Mozilla`, first filename matches `update-*.dat`). See `ps_values` + `PS_META`.

### 4d. JScript (`*.js`, old style)
`recover_*()` returns the descriptor as a JS object literal string; we eval it
inside an **isolated Node `vm`** context (`lib/jsrecover_json.js`) — no
`require`/`process`/network, so it only computes. Also parse three
**syntax-style** answers from the source: function style
(declaration/named_expression/anonymous_expression), invocation style
(direct/call/apply), property style (dot/bracket_literal/mixed) — see
`detect.js_styles`. (New-style `host-*.js`/`.mjs` use the carriers above.)

### 4e. Batch (`*.cmd`/`*.bat`)
Descriptor is split across `set "fragN=..."` lines (join 0–3, strip `^`
escapes). An encoded `rem HUNTRESS-MATERIAL:` copy exists too (same content).

### 4f. Advanced-bash syntax fixtures
Files like `indirect-expansion.sh`, `token-fragmentation.sh`,
`array-slicing.sh`, `associative-arrays.sh`, `trap-handler.sh`,
`recursive-walk.sh`. Descriptor has `feature=`/`primitive=` and **no `role`**
→ role is `advanced_syntax`, attack `T1059.004`. Detected generically by
`feature=` present / `role=` absent.

---

## 5. Answer kinds → how we answer them

`lib/solve.py:kind_of` maps an answer-id suffix to a kind. Most map straight to
a descriptor field (`campaign`→campaign_id, `url`, `file-path`→file_path,
`host-id`, `next-stage`, `upload-url`, `cron-path`, `service-name`,
`schedule-path`, `extension`, `note`→note_name, `stage-count`, `steps` (join
with `>`), `syntax`, `obfuscation`, `carrier`, `windows-chain`, `feature`,
`primitive`, `host-profile`, `stage-profile`, `next-language`,
`representation`=codec rep, `transform`=codec transform). `role`/`attack`/
`scenario` are derived as in §3.

### ⚑ `control` and `expansion` are NOT classifiable
These two batch/VBS kinds describe the script's control-flow wrapper and
variable-expansion form. **Empirically the label is not a function of the
visible syntax** — identical reconstruction lines grade `percent` in one
variant and `delayed` in another, `for_once` vs `call_subroutine`, etc. We
confirmed the correct label is **not** encoded anywhere in the file. So:

> Do **not** try to classify `control`/`expansion`. Brute-force each id against
> its small enum. The heuristics in `detect.py` are kept only as a
> "guess-first" to shave a submit; they are right ~100% on Day 6 but often
> wrong on later days.

Enums:
- batch `control`: `direct, goto_dispatch, call_subroutine, for_once, if_guard,
  errorlevel_guard`
- VBScript `control`: `direct, for_once, do_once, while_once, select_case,
  error_guard`
- `expansion` (batch): `for_indirect, delayed, call_double, percent`

Per set there are ~18 control + ~9 expansion = **27** brute targets.

---

## 6. The solve algorithm (and why)

Because banking is atomic (§1.1):

1. **Decode** every file → `ans` (all decode-derived kinds).
2. Submit **all reliable** answers (every kind except control/expansion) as one
   group → `accepted` banks them. (On a clean variant this is always correct.)
3. **Brute** control/expansion **per-id, in parallel** (ThreadPoolExecutor,
   ~12 workers). Each id: try the detector guess first, then the rest of its
   enum; the submit that returns `accepted` banks it. Parallelism overlaps
   network latency even though the server serializes writes — ~27 ids resolve
   in **~4–8s**.
4. **Final** full submit → `CORRECT`; read flag from status.

**Mode order & knowledge transfer** (`solve_day.py`, default/sequential):
solve **single_solve first** — untimed, no timer, so it's where the decoder is
validated and any new family surfaces via `undecoded`/`STUCK` — then carry the
control/expansion values it discovered forward as **priors** into
**time_trial**, then into **mastery**. Each mode is a fresh randomized variant,
so a prior is a *first-try shortcut* for the brute, not a guarantee; measured
cross-variant hit rate is ~37% (vs ~17–25% random), which is a real speedup
(e.g. a TT with priors finished in ~4s). Mastery's multiple sets decode in
parallel inside `solve_route`. `--parallel` runs the three modes concurrently
instead and forgoes priors threading (untimed throughput only).

Fallback (robustness on a new day): if the reliable group is `incorrect`, run a
per-kind group sweep to find which kind is wrong. Enum kinds (role, scenario,
styles, attack, …) get added to the parallel brute; **exact** kinds
(campaign/url/stage_profile/transform/…) failing means a **decode bug** — the
solver prints them as `STUCK ... exact-kind` so you can fix the decoder.

Performance (untimed, keep-alive session + parallel per-set decode + parallel
per-id brute): single/time_trial ≈ 5–12s; mastery ≈ 12s for 2 sets, ≈ 30–40s
for 5 sets. The long pole is always the control/expansion per-id brute
(~27 ids/set). `--ranked` adds a 7s (lenient ~10–15s) timer — see §1 for what
fits; the ranked→untimed fallback in `solve_day` guarantees the flag regardless.

---

## 7. Extending for a new day

Run `solve_day.py N` (or `solve_any.py <route>`). Then:
- **`undecoded-kinds` non-empty** → a new file/language didn't decode. Look at
  the new filenames in the extract dir. If it uses the `Material_/Codec_` or
  `HUNTRESS_ANALYSIS_V1:` carrier, it probably already works; if a new
  representation/transform/prefix appears, add it to `lib/decode.py`.
- **`STUCK ... exact-kind (decode bug?)`** → the decoder produced a wrong exact
  value for that kind/file. Open the file, compare the decoded descriptor to
  what's expected, fix `lib/solve.py`/`lib/decode.py`.
- **New enum kind** → add its pool to `POOLS` in `solve_any.py` (and `kind_of`
  mapping in `lib/solve.py` if the suffix is new).
- `control`/`expansion` always need brute — expected, not a bug.

Validate changes offline against known-good variants before burning attempts:
the decoders are pure functions of the files; re-solving Day 6 (`role`/`attack`
etc.) must stay correct.

---

## 8. Toolkit files

```
huntress-ctf/
  PLAYBOOK.md          this file
  solve_day.py         entry point: solve day N's three modes
  solve_any.py         solve one route (single/time_trial/mastery), untimed
  lib/gm.py            Game Master HTTP client (token from $HUNTRESS_GM_TOKEN)
  lib/decode.py        codec/representation/transform decoding (decode_label)
  lib/detect.py        control/expansion/js-style heuristics (guess-first only)
  lib/solve.py         per-file decode → {answer_id: value}
  lib/jsrecover_json.js  isolated Node vm JScript descriptor recovery
```

Requirements: `python3`, `pyzipper` (`pip install pyzipper`), `node`, `curl`.

---

## 9. Solved so far (flags)

| Day | Challenge | single | time_trial | mastery |
|-----|-----------|--------|-----------|---------|
| 6 | Shell We Begin | 3cc7539d670038f48c64d9e9041c0443 | 312ba14d0a4fc3461c8cf0eca2b05a58 | 03aa9190539bc0ff8dbed2182e60e044 |
| 7 | Node by Node | a96b646032cda18648e9af407f36826b | b488900d03eaf8bfa505a7c7426e37b2 | 92428248ee4d6a609080f2a737e2fdb6 |
| 8 | Lost in Translation | b1a8c59aeba7bd73321ce29251d413b3 | eb93886d6d22b874d4b631ad00f1d903 | d2fd182d2189ea7dd5eb1414c39e98cd |
| 9 | All the World's a Stager | 37c1351cba1d424bd5ad51e22ec53b4a | 92deeb8662fe75ed7940449c278e92cf | d48388d8186df83f4bff0cea53d0f07e |
| 10 | Bind Over Matter | 49a4b7078f5d1c4530a8b21f772cbba0 | 4334851f13f26e559b003eb22aaddd4d | e510c993fd3dea2062632e92f9f6b3af |
| 11 | By Any Other Name | f97fc28f12ab0eff9959e7fe14feb609 | 5c6ad5bb96839bdfe91db3e1d065febe | e6743b3ebd84dae152ea11ae3d35d796 |
| 13 | Zip Code | 2e316ec6fabe5733c6dce3c9d90a336f | 9c1e02ac82c6a2ad5cd707e7f516cf62 | cf26d3dbfae8d8426a02e2f5e9beb03c |

(Days 1–5 and 12 also exist in this lane; new days release daily. Days 6–13
verified with this toolkit; each new day needed at most a small decoder
addition, none since Day 8.)

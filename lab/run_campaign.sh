#!/usr/bin/env bash
# Runs a pre-registered benchmark campaign on the lab (docs/plan/12 §2, §7).
# usage: lab/run_campaign.sh [--pilot [--set KEY=VALUE]...] [--dry-run] lab/campaigns/<name>.toml
#
# The campaign file names: target, methodology, profile, ifaces, build preset,
# repetitions, and the command lines. In commands, {out}, {rep} and {build} are
# substituted, and so is {key} for every top-level string or number of the file (e.g.
# {input_sha256}) and {table.key} for the values of its tables (e.g. {coalescing.epoll}).
# Optional:
#   setup    = [...]   run once before the repetitions (e.g. the reflector calibration)
#   finalize = [...]   run once after them (e.g. derived statistics)
#   [matrix]           arrays of values; every command of a repetition runs once per
#                      combination, with {name} and {cell} (the combination, e.g.
#                      "xsk-1000000") substituted
#   continue_on_error = true   a failing command is recorded in failures.txt and the
#                      campaign goes on (e.g. a variant the lab kernel cannot run is
#                      reported missing, never replaced)
# Results land in results/<yyyy-mm-dd>-<target>-<short-sha>/ and must be committed via PR.
#
# Pre-registration (METHODOLOGY §18, plan 12 §2): any value of the form "TBD_..."
# (TBD_BY_PILOT, TBD_BY_T20, TBD_BY_OWNER) marks a parameter that labelled pilot runs or
# an owner decision fix before the headline campaign; a file named by a *_profile key
# whose `status` is not "registered" counts the same. Such a campaign is refused. With
# --pilot it runs as a labelled pilot: every TBD value must be given with --set, the
# folder is results/<date>-<target>-pilot-<sha>/ and campaign.toml records the
# overrides. --set without --pilot is refused (headline values live in the committed
# file). --dry-run prints the commands without building or running anything.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pilot=0; dry=0; sets=()
while [[ $# -gt 1 ]]; do
  case "$1" in
    --pilot) pilot=1; shift ;;
    --dry-run) dry=1; shift ;;
    --set) sets+=("$2"); shift 2 ;;
    *) break ;;
  esac
done
cfg="${1:?usage: lab/run_campaign.sh [--pilot [--set KEY=VALUE]...] [--dry-run] CAMPAIGN.toml}"
[[ -f "$cfg" ]] || { echo "no such campaign: $cfg" >&2; exit 64; }
if [[ $pilot -eq 0 && ${#sets[@]} -gt 0 ]]; then
  echo "refusing: --set is for labelled pilot runs (--pilot); headline values must be in $cfg" >&2
  exit 1
fi

sha=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo 0000000)
# The plan, NUL-separated in a file: label, profile, ifaces, preset, continue_on_error,
# then "S<cmd>", "R<rep>\t<cmd>", "F<cmd>" (values after any --set overrides).
planf=$(mktemp)
trap 'rm -f "$planf"' EXIT
CFG="$cfg" ROOT="$root" PILOT=$pilot SETS="$(printf '%s\n' "${sets[@]+"${sets[@]}"}")" python3 - > "$planf" <<'PY'
import itertools, os, re, sys, tomllib
cfg = os.environ["CFG"]; root = os.environ["ROOT"]; pilot = os.environ["PILOT"] == "1"
d = tomllib.load(open(cfg, "rb"))
overrides = {}
for line in os.environ["SETS"].splitlines():
    if not line.strip():
        continue
    if "=" not in line:
        sys.exit(f"bad --set {line!r} (KEY=VALUE)")
    k, v = line.split("=", 1)
    overrides[k.strip()] = v.strip()

def flat(prefix, obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            flat(f"{prefix}.{k}" if prefix else k, v, out)
    else:
        out[prefix] = obj
    return out

values = flat("", d, {})
for k, v in overrides.items():
    if k not in values:
        sys.exit(f"--set {k}: no such key in {cfg}")
    values[k] = v
# Pre-registration check.
tbd = []
for k, v in values.items():
    vs = v if isinstance(v, list) else [v]
    for x in vs:
        if isinstance(x, str) and x.startswith("TBD_"):
            tbd.append(f"{k} = {x}")
for k, v in values.items():
    if k.endswith("_profile") and isinstance(v, str):
        p = v if os.path.isabs(v) else os.path.join(root, v)
        try:
            text = open(p).read()
        except OSError:
            sys.exit(f"{k}: cannot read {v}")
        m = re.search(r"^\s*status\s*=\s*(\S+)", text, re.M)
        status = m.group(1) if m else "missing"
        if status != "registered":
            tbd.append(f"{k} ({v}): status {status}")
if tbd and not pilot:
    print("refusing: not pre-registered (METHODOLOGY §18; run labelled pilots with --pilot --set KEY=VALUE):", file=sys.stderr)
    for t in tbd:
        print(f"  {t}", file=sys.stderr)
    sys.exit(3)
if pilot:
    left = [t for t in tbd if " = TBD_" in t]  # a draft profile is what pilots run
    if left:
        print("refusing: a pilot must give every TBD value with --set:", file=sys.stderr)
        for t in left:
            print(f"  {t}", file=sys.stderr)
        sys.exit(3)

def subst(s, extra):
    def rep(m):
        k = m.group(1)
        if k in extra:
            return str(extra[k])
        v = values.get(k)
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            return str(v)
        return m.group(0)
    return re.sub(r"\{([A-Za-z0-9_.-]+)\}", rep, s)

matrix = d.get("matrix", {})
keys = list(matrix.keys())
combos = [dict(zip(keys, c)) for c in itertools.product(*[matrix[k] for k in keys])] if keys else [{}]
def val(k, default=""):
    v = values.get(k, default)
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v)
ifaces = values.get("ifaces", [])
ifaces = " ".join(ifaces) if isinstance(ifaces, list) else str(ifaces)
out = [d["target"] + ("-pilot" if pilot else ""), val("profile"), ifaces, val("preset"),
       "1" if d.get("continue_on_error") else "0"]
for c in d.get("setup", []):
    out.append("S" + subst(c, {}))
for r in range(1, int(d["repetitions"]) + 1):
    for combo in combos:
        cell = "-".join(str(combo[k]) for k in keys) if keys else ""
        extra = dict(combo)
        extra["cell"] = cell
        extra["rep"] = f"{r:02d}"
        for c in d["commands"]:
            out.append(f"R{r:02d}\t" + subst(c, extra))
for c in d.get("finalize", []):
    out.append("F" + subst(c, {}))
sys.stdout.write("\0".join(out))
PY
mapfile -d '' -t items < "$planf"
label="${items[0]}"; profile="${items[1]}"; ifaces="${items[2]}"; preset="${items[3]}"; keep_going="${items[4]}"
[[ -n "$label" ]] || { echo "campaign file lacks target" >&2; exit 64; }
out="$root/results/$(date +%F)-$label-$sha"
build="$root/build/$preset"
expand() { local s=$1; s=${s//\{out\}/$out}; s=${s//\{build\}/$build}; echo "$s"; }

if [[ $dry -eq 1 ]]; then
  echo "results: $out (dry run)"
  echo "profile: $profile; ifaces: $ifaces; preset: $preset"
  for it in "${items[@]:5}"; do
    case "${it:0:1}" in
      S) echo "[setup] $(expand "${it:1}")" ;;
      R) echo "[rep ${it:1:2}] $(expand "${it:4}")" ;;
      F) echo "[finalize] $(expand "${it:1}")" ;;
    esac
  done
  exit 0
fi

[[ -z "$(git -C "$root" status --porcelain -- src apps bench)" ]] || { echo "refusing: uncommitted changes in src/apps/bench" >&2; exit 1; }
mkdir -p "$out"
cp "$cfg" "$out/campaign.toml"
if [[ $pilot -eq 1 ]]; then
  { echo; echo "# labelled pilot run (lab/run_campaign.sh --pilot)"; echo "[pilot_overrides]";
    for s in "${sets[@]+"${sets[@]}"}"; do echo "\"${s%%=*}\" = \"${s#*=}\""; done; } >> "$out/campaign.toml"
fi

"$root/lab/verify_env.sh" "$profile" "$out" $ifaces
cmake --preset "$preset" -S "$root" >/dev/null
cmake --build "$root/build/$preset" -j >/dev/null

for it in "${items[@]:5}"; do
  case "${it:0:1}" in
    S) run=$(expand "${it:1}"); echo "[setup] $run" ;;
    R) run=$(expand "${it:4}"); echo "[rep ${it:1:2}] $run" ;;
    F) run=$(expand "${it:1}"); echo "[finalize] $run" ;;
    *) continue ;;
  esac
  if ! bash -c "$run"; then
    [[ $keep_going -eq 1 && "${it:0:1}" == R ]] || { echo "command failed: $run" >&2; exit 1; }
    echo "$run" >> "$out/failures.txt"
  fi
done
python3 "$root/tools/results/summarize.py" "$out" 2>/dev/null || echo "(summary tool not available yet)"
echo "results: $out"

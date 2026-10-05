#!/usr/bin/env python3
"""Re-verify every counted DST bug (docs/plan/09 §10, T23a). Weekly and on ledger change.

For each counted bug in sim/ledger/bugs.yaml:
  1. check out tag dst/DST-NNN/found (falling back to sha_found) in a git
     worktree, build exsim (LLE_SIM=ON), run the seed with its exsim_args, and
     require the recorded signature (oracle, event index, message hash);
  2. check out tag dst/DST-NNN/fix (falling back to fix_sha), build, run the
     same seed, and require it to pass;
  3. require tests/sim_regressions/DST-NNN_* to exist at HEAD, pass at HEAD,
     and fail at sha_found (the HEAD copy of tests/sim_regressions/ is placed
     into the found worktree; a test that cannot even build there is reported
     as "unbuildable", which does not verify).
Builds can run inside a pinned container image (--container IMAGE) so that
runner-image drift cannot break old builds.

Until the owner commits and tags, an entry may say sha_found/fix_sha:
"uncommitted". The fix tree is then a copy of the working tree (tracked and
untracked files, .gitignore respected) and the found tree is that copy with
found_patch applied (git apply -p1), i.e. the fix reverted.

    python3 tools/ledger/verify_bugs.py [--ledger F] [--id DST-NNN]... [--container IMAGE]
                                        [--workdir D] [--jobs N] [--json out.jsonl] [--dry-run]

Exit status: 0 when every counted bug verified (vacuously true for an empty
ledger), 1 when any failed, 2 on a usage or ledger-validation error.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ledger  # noqa: E402

REGRESSION_DIR = "tests/sim_regressions"


@dataclass
class Ctx:
    repo: Path
    workdir: Path
    container: str | None
    jobs: int
    dry_run: bool
    keep: bool
    timeout: int
    only: str = ""
    log: list[str] = field(default_factory=list)


def sh(ctx: Ctx, cmd: list[str], cwd: Path, timeout: int | None = None, mounts: tuple[Path, ...] = ()) -> subprocess.CompletedProcess:
    """Runs cmd (inside the container when configured). Never raises on failure."""
    if ctx.container:
        vols: list[str] = []
        for m in {ctx.workdir, ctx.repo, *mounts}:
            vols += ["-v", f"{m}:{m}"]
        cmd = ["docker", "run", "--rm", *vols, "-w", str(cwd), ctx.container, *cmd]
    ctx.log.append(f"$ (cd {cwd} && {shlex.join(cmd)})")
    if ctx.dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout or ctx.timeout)
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return subprocess.CompletedProcess(cmd, 124, out, "timeout")


def git(ctx: Ctx, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ctx.repo, capture_output=True, text=True)


def resolve_ref(ctx: Ctx, tag: str, sha: str | None) -> tuple[str | None, str]:
    r = git(ctx, "rev-parse", "--verify", "-q", f"refs/tags/{tag}^{{commit}}")
    if r.returncode == 0:
        return r.stdout.strip(), f"tag {tag}"
    if sha:
        r = git(ctx, "rev-parse", "--verify", "-q", f"{sha}^{{commit}}")
        if r.returncode == 0:
            return r.stdout.strip(), f"sha {sha} (tag {tag} missing)"
    return None, f"neither tag {tag} nor sha {sha} is fetchable"


class Worktree:
    """A source tree to build: a git worktree at `ref`, or (ref None) a copy of
    the working tree with an optional patch applied."""

    def __init__(self, ctx: Ctx, ref: str | None, name: str, patch: Path | None = None):
        self.ctx, self.ref, self.patch = ctx, ref, patch
        self.path = ctx.workdir / name

    def __enter__(self) -> Path:
        if self.path.exists():
            git(self.ctx, "worktree", "remove", "--force", str(self.path))
            shutil.rmtree(self.path, ignore_errors=True)
        if self.ref is not None:
            self.ctx.log.append(f"$ git worktree add --detach {self.path} {self.ref}")
            if not self.ctx.dry_run:
                r = git(self.ctx, "worktree", "add", "--detach", str(self.path), self.ref)
                if r.returncode != 0:
                    raise RuntimeError(f"git worktree add failed: {r.stderr.strip()}")
            return self.path
        self.ctx.log.append(f"$ copy working tree -> {self.path}")
        if not self.ctx.dry_run:
            copy_working_tree(self.ctx.repo, self.path)
        if self.patch is not None:
            self.ctx.log.append(f"$ (cd {self.path} && git apply {self.patch})")
            if not self.ctx.dry_run:
                r = subprocess.run(["git", "apply", "--whitespace=nowarn", str(self.patch)], cwd=self.path,
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    raise RuntimeError(f"found_patch does not apply: {r.stderr.strip()}")
        return self.path

    def __exit__(self, *exc: object) -> None:
        if self.ctx.keep or self.ctx.dry_run:
            return
        if self.ref is not None:
            git(self.ctx, "worktree", "remove", "--force", str(self.path))
        shutil.rmtree(self.path, ignore_errors=True)


def copy_working_tree(repo: Path, dst: Path) -> None:
    r = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo,
                       capture_output=True, check=True)
    for rel in sorted(x for x in r.stdout.decode().split("\0") if x):
        src = repo / rel
        if not src.is_file():
            continue  # deleted but still in the index
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)


def tree_for(ctx: Ctx, bug: dict, which: str) -> tuple[Worktree | None, str]:
    """The found or fix tree of a bug, from tags, shas, or the uncommitted working tree."""
    bid = str(bug.get("id"))
    sha = bug.get("sha_found" if which == "found" else "fix_sha")
    if sha == ledger.UNCOMMITTED:
        if which == "fix":
            return Worktree(ctx, None, f"{bid}-fix"), "uncommitted working tree"
        patch = ctx.repo / str(bug.get("found_patch"))
        if not patch.is_file():
            return None, f"found_patch {bug.get('found_patch')} missing"
        return Worktree(ctx, None, f"{bid}-found", patch), f"working tree + {bug.get('found_patch')}"
    ref, how = resolve_ref(ctx, f"dst/{bid}/{which}", sha)
    return (Worktree(ctx, ref, f"{bid}-{which}") if ref else None), how


def configure_and_build(ctx: Ctx, src: Path, build: Path, targets: list[str], tests: bool) -> tuple[bool, str]:
    cfg = [
        "cmake", "-S", str(src), "-B", str(build), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DLLE_SIM=ON",
        f"-DLLE_BUILD_TESTS={'ON' if tests else 'OFF'}", "-DLLE_BUILD_BENCH=OFF", "-DLLE_BUILD_FUZZ=OFF",
        "-DLLE_BUILD_APPS=OFF",
    ]
    if ctx.only:
        cfg.append(f"-DLLE_ONLY={ctx.only}")
    r = sh(ctx, cfg, src, mounts=(src,))
    if r.returncode != 0:
        return False, f"configure failed: {(r.stderr or r.stdout)[-2000:]}"
    b = ["cmake", "--build", str(build), "-j", str(ctx.jobs)]
    for t in targets:
        b += ["--target", t]
    r = sh(ctx, b, src, mounts=(src,))
    if r.returncode != 0:
        return False, f"build failed: {(r.stderr or r.stdout)[-2000:]}"
    return True, ""


def parse_exsim(stdout: str) -> dict:
    out: dict = {"result": None, "signature": None, "world": None}
    for line in stdout.splitlines():
        if line.startswith("signature="):
            parts = dict(p.split("=", 1) for p in line.split() if "=" in p)
            out["signature"] = parts.get("signature")
            out["world"] = parts.get("world")
        elif line.startswith("result="):
            out["result"] = line.split("=", 1)[1].strip()
    return out


def exsim_cmd(exsim: Path, bug: dict) -> list[str]:
    seed = ledger.parse_seed(bug.get("seed"))
    return [str(exsim), f"--seed=0x{seed:016x}", *[str(a) for a in (bug.get("exsim_args") or [])]]


def run_seed(ctx: Ctx, src: Path, build: Path, bug: dict) -> dict:
    exsim = build / "sim" / "exsim"
    r = sh(ctx, exsim_cmd(exsim, bug), src, mounts=(src,))
    res = parse_exsim(r.stdout)
    res["exit"] = r.returncode
    return res


def same_signature(recorded: dict | None, observed: str | None) -> bool:
    obs = ledger.parse_signature(observed) if observed else None
    return recorded is not None and obs is not None and recorded == obs


def verify_one(ctx: Ctx, bug: dict) -> dict:
    bid = str(bug.get("id"))
    rec: dict = {"id": bid, "verified": False, "steps": {}, "errors": []}
    recorded = ledger.parse_signature(bug.get("signature"))

    # 1. The seed reproduces its signature at the found commit.
    tree, how = tree_for(ctx, bug, "found")
    rec["steps"]["found_ref"] = how
    if tree is None:
        rec["errors"].append(how)
        return rec
    try:
        with tree as wt:
            build = wt / "build-verify"
            ok, err = configure_and_build(ctx, wt, build, ["exsim"], tests=False)
            if not ok:
                rec["errors"].append(f"found: {err}")
                return rec
            res = run_seed(ctx, wt, build, bug)
            rec["steps"]["found"] = res
            if not ctx.dry_run and not same_signature(recorded, res["signature"]):
                rec["errors"].append(
                    f"found: signature {res['signature']} != recorded {ledger.format_signature(recorded) if recorded else None}")

            # 3b. The regression test fails at the found commit.
            reg = regression_files(ctx)
            mine = [p for p in reg if p.name.startswith(f"{bid}_")]
            rec["steps"]["regression_files"] = [str(p.relative_to(ctx.repo)) for p in mine]
            if not mine and not ctx.dry_run:
                rec["errors"].append(f"regression: no {REGRESSION_DIR}/{bid}_* at HEAD")
            elif mine or ctx.dry_run:
                dst = wt / REGRESSION_DIR
                ctx.log.append(f"$ cp -R {ctx.repo / REGRESSION_DIR} {dst}")
                if not ctx.dry_run:
                    shutil.copytree(ctx.repo / REGRESSION_DIR, dst, dirs_exist_ok=True)
                ok, err = configure_and_build(ctx, wt, wt / "build-regress", [], tests=True)
                if not ok:
                    rec["steps"]["regression_at_found"] = "unbuildable"
                    rec["errors"].append(f"regression: unbuildable at sha_found ({err[:200]})")
                else:
                    r = sh(ctx, ["ctest", "--test-dir", str(wt / "build-regress"), "-R", f"^{bid}_"], wt, mounts=(wt,))
                    ran = "No tests were found" not in r.stdout
                    rec["steps"]["regression_at_found"] = "fails" if r.returncode != 0 else "passes"
                    if not ctx.dry_run and (r.returncode == 0 or not ran):
                        rec["errors"].append("regression: test does not fail at sha_found" if ran else
                                             "regression: test not registered with ctest")
    except RuntimeError as e:
        rec["errors"].append(str(e))
        return rec

    # 2. The fix commit passes the same seed.
    ftree, fhow = tree_for(ctx, bug, "fix")
    rec["steps"]["fix_ref"] = fhow
    if ftree is None:
        rec["errors"].append(fhow)
    else:
        try:
            with ftree as wt:
                build = wt / "build-verify"
                ok, err = configure_and_build(ctx, wt, build, ["exsim"], tests=False)
                if not ok:
                    rec["errors"].append(f"fix: {err}")
                else:
                    res = run_seed(ctx, wt, build, bug)
                    rec["steps"]["fix"] = res
                    if not ctx.dry_run and res["result"] != "PASS":
                        rec["errors"].append(f"fix: seed still fails ({res['signature'] or res['exit']})")
        except RuntimeError as e:
            rec["errors"].append(str(e))

    # 3a. The regression test passes at HEAD.
    if regression_files(ctx) or ctx.dry_run:
        build = ctx.workdir / "head-build"
        ok, err = configure_and_build(ctx, ctx.repo, build, [], tests=True)
        if not ok:
            rec["errors"].append(f"regression: HEAD {err[:200]}")
        else:
            r = sh(ctx, ["ctest", "--test-dir", str(build), "-R", f"^{bid}_"], ctx.repo)
            rec["steps"]["regression_at_head"] = "passes" if r.returncode == 0 else "fails"
            if not ctx.dry_run and r.returncode != 0:
                rec["errors"].append("regression: test fails at HEAD")
    rec["verified"] = not rec["errors"]
    return rec


def regression_files(ctx: Ctx) -> list[Path]:
    d = ctx.repo / REGRESSION_DIR
    # One file or one directory (own CMakeLists.txt) per bug: tests/sim_regressions/DST-NNN_*.
    return sorted(d.glob("DST-*_*")) if d.is_dir() else []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", default=str(ledger.DEFAULT_LEDGER))
    ap.add_argument("--repo", default=str(ledger.REPO))
    ap.add_argument("--id", action="append", default=[], help="verify only these ids (repeatable)")
    ap.add_argument("--workdir", help="scratch directory for worktrees and builds (default: a temp dir)")
    ap.add_argument("--container", help="pinned image to build and run in (docker)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per command")
    ap.add_argument("--json", help="append one JSON line per bug to this file")
    ap.add_argument("--only", default="", help="LLE_ONLY path prefixes for the builds (e.g. 'src/common;src/env;sim')")
    ap.add_argument("--keep-worktrees", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; check out and build nothing")
    a = ap.parse_args()

    data = ledger.load(a.ledger)
    problems = ledger.validate(data)
    if problems:
        for p in problems:
            print(f"verify_bugs: ledger: {p}", file=sys.stderr)
        return 2
    bugs = ledger.counted(data)
    if a.id:
        bugs = [b for b in bugs if b.get("id") in a.id]
    tmp = None
    if a.workdir:
        workdir = Path(a.workdir).resolve()
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory(prefix="verify_bugs_")
        workdir = Path(tmp.name)
    ctx = Ctx(Path(a.repo).resolve(), workdir, a.container, a.jobs, a.dry_run, a.keep_worktrees, a.timeout, a.only)
    results = []
    for bug in bugs:
        rec = verify_one(ctx, bug)
        results.append(rec)
        state = "VERIFIED" if rec["verified"] else "FAILED"
        print(f"{rec['id']}: {state}" + ("" if rec["verified"] else " - " + "; ".join(rec["errors"])))
    if a.dry_run:
        print("\n".join(ctx.log))
    if a.json:
        with open(a.json, "a") as f:
            for rec in results:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
    verified = sum(1 for r in results if r["verified"])
    print(f"verify_bugs: counted={len(bugs)} verified={verified} failed={len(bugs) - verified}"
          f"{' (dry run)' if a.dry_run else ''}")
    if tmp is not None and not a.keep_worktrees:
        tmp.cleanup()
    return 0 if verified == len(bugs) or a.dry_run else 1


if __name__ == "__main__":
    sys.exit(main())

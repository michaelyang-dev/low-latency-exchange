#!/usr/bin/env python3
"""Self-test of the M13 result tools on synthetic campaign folders (no lab data).

usage: python3 tools/results/test_instruments.py
Covers summarize.py (cells; the T18, T19, T20 and T32 derived blocks), merge_t20.py and
irq_delta.py.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import summarize  # noqa: E402


def write(p: Path, obj) -> None:
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)


class Summaries(unittest.TestCase):
    def folder(self, toml: str) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "campaign.toml").write_text(toml)
        return d

    def test_t18_headline_and_exclusions(self):
        d = self.folder('target = "t18"\nmethodology = "methodology-v2"\npass_p50_ns = 14000\npass_p99_ns = 38000\n')
        for i, (p50, p99) in enumerate([(9000, 20000), (9500, 21000), (9100, 50000)], 1):
            write(d / f"run-{i:02d}.json", {"valid": True, "ttt_raw_p50_ns": p50, "ttt_raw_p99_ns": p99})
        write(d / "run-04.json", {"valid": False, "ttt_raw_p50_ns": 1, "ttt_raw_p99_ns": 1})
        s = summarize.summarize(d)
        self.assertEqual(s["runs_valid"], 3)
        self.assertEqual(s["runs_excluded"], 1)
        self.assertEqual(s["derived"]["median_p50_ns"], 9100)
        self.assertEqual(s["derived"]["median_p99_ns"], 21000)
        self.assertTrue(s["derived"]["pass"])

    def test_t19_ratio_with_bca(self):
        d = self.folder('target = "t19"\nratio_numerator = "epoll"\nratio_denominator = "afxdp"\n'
                        'ratio_metric = "ttt_raw_p99_ns"\npass_ratio = 3.1\n[matrix]\ncell = ["epoll", "afxdp"]\n')
        for i in range(1, 11):
            write(d / f"run-{i:02d}-epoll.json", {"valid": True, "ttt_raw_p99_ns": 100000 + 1000 * i})
            write(d / f"run-{i:02d}-afxdp.json", {"valid": True, "ttt_raw_p99_ns": 25000 + 100 * i})
        s = summarize.summarize(d)
        r = s["derived"]
        self.assertAlmostEqual(r["ratio"], 105500 / 25550, places=6)
        lo, hi = r["ci95_bca"]
        self.assertLess(lo, r["ratio"])
        self.assertGreater(hi, r["ratio"])
        self.assertTrue(r["pass"])
        self.assertEqual(set(s["cells"]), {"epoll", "afxdp"})
        self.assertEqual(s["cells"]["epoll"]["runs_valid"], 10)

    def test_t20_search(self):
        d = self.folder('target = "t20"\npass_rate = 4200000\n')
        write(d / "search.json", {"highest_valid_rate": 4300000, "points": [{"rate": 4300000, "pass": True}]})
        write(d / "rate-4300000-run-01.json", {"valid": True})
        write(d / "rate-4400000-run-01.json", {"valid": False, "invalid_conditions": "backlog_ok"})
        s = summarize.summarize(d)
        self.assertTrue(s["derived"]["pass"])
        self.assertEqual(s["derived"]["runs"]["rate-4400000"][0]["invalid_conditions"], "backlog_ok")

    def test_t32_overhead(self):
        d = self.folder('target = "t32"\npass_overhead_pct = 3.0\n[matrix]\nslot = ["A1", "B1"]\n')
        write(d / "run-01-A1.json", {"valid": True, "arm": "on", "work_ns_per_msg_x1000": 1020000})
        write(d / "run-01-B1.json", {"valid": True, "arm": "off", "work_ns_per_msg_x1000": 1000000})
        s = summarize.summarize(d)
        self.assertAlmostEqual(s["derived"]["overhead_pct"], 2.0, places=6)
        self.assertTrue(s["derived"]["pass_overhead"])


class Merges(unittest.TestCase):
    def test_merge_t20_requires_every_condition(self):
        d = Path(tempfile.mkdtemp())
        base = {"responses_valid": True, "lateness_ok": True, "slo_evaluated": True, "slo_ok": True, "valid": False}
        write(d / "r.json", base)
        write(d / "b.json", {"backlog_evaluated": True, "backlog_ok": True})
        write(d / "i.json", {"irq_clean": True, "irq_matched_delta": 0})
        subprocess.run([sys.executable, str(HERE / "merge_t20.py"), str(d / "r.json"), str(d / "b.json"), str(d / "i.json")],
                       check=True, capture_output=True)
        self.assertTrue(json.loads((d / "r.json").read_text())["valid"])
        write(d / "r.json", base)
        write(d / "i.json", {"irq_clean": False, "irq_matched_delta": 3})
        subprocess.run([sys.executable, str(HERE / "merge_t20.py"), str(d / "r.json"), str(d / "b.json"), str(d / "i.json")],
                       check=True, capture_output=True)
        r = json.loads((d / "r.json").read_text())
        self.assertFalse(r["valid"])
        self.assertEqual(r["invalid_conditions"], "irq_clean")
        write(d / "r.json", base)  # no backlog verdict at all: never valid by default
        subprocess.run([sys.executable, str(HERE / "merge_t20.py"), str(d / "r.json"), str(d / "none.json"),
                        str(d / "i.json")], check=True, capture_output=True)
        self.assertIn("backlog_ok", json.loads((d / "r.json").read_text())["invalid_conditions"])

    def test_irq_delta(self):
        d = Path(tempfile.mkdtemp())
        before = ("           CPU0       CPU1       CPU8\n"
                  " 120:         10          0          5   PCI-MSI 1  mlx5_comp0@pci:0000:41:00.0\n"
                  " 121:          0          0          9   PCI-MSI 2  nvme0q1\n"
                  " LOC:        100        100        100   Local timer interrupts\n")
        after = ("           CPU0       CPU1       CPU8\n"
                 " 120:         10          0        500   PCI-MSI 1  mlx5_comp0@pci:0000:41:00.0\n"
                 " 121:          0          2         90   PCI-MSI 2  nvme0q1\n"
                 " LOC:        900        900        900   Local timer interrupts\n")
        sb = "                    CPU0       CPU1       CPU8\n      NET_RX:          1          0        100\n"
        sa = "                    CPU0       CPU1       CPU8\n      NET_RX:          1          0        900\n"
        for n, t in (("b", before), ("a", after), ("sb", sb), ("sa", sa)):
            (d / n).write_text(t)
        out = subprocess.run([sys.executable, str(HERE / "irq_delta.py"), str(d / "b"), str(d / "a"), "--softirq",
                              str(d / "sb"), str(d / "sa"), "--cpus", "0-7"], check=True, capture_output=True, text=True)
        j = json.loads(out.stdout)
        self.assertEqual(j["irq_matched_delta"], 2)  # nvme on CPU1; CPU8 is the exchange's own set
        self.assertEqual(j["softirq_delta"], 0)
        self.assertFalse(j["irq_clean"])


if __name__ == "__main__":
    unittest.main(verbosity=1)

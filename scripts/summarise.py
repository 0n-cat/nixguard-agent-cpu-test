"""Turns out/samples.csv into the job summary (Markdown on stdout), out/summary.md, out/intervals.csv
and out/cpu.png.

CPU is worked out from each process's cumulative CPU time between samples, so short bursts are counted
in full. It is given two ways: % of one core (what Activity Monitor shows per process) and % of the
whole machine (one core's % divided by the number of cores)."""
import csv
import os
import re
import statistics
import sys
from collections import defaultdict

out = sys.argv[1] if len(sys.argv) > 1 else "out"


def seconds(text):
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    parts = [float(p) for p in text.split(":")]
    total = 0.0
    for p in parts:
        total = total * 60 + p
    return days * 86400 + total


def label(command):
    first = command.split(" ")[0]
    name = os.path.basename(first)
    if name in ("bash", "sh") and "/Library/Ossec" in command:
        name = os.path.basename(command.split(" ")[1]) if " " in command else name
    if name == "log":
        name = "log stream (macOS log, read by wazuh-logcollector)"
    return name


machine = {}
try:
    for line in open(os.path.join(out, "machine.txt")):
        if ":" in line:
            k, v = line.split(":", 1)
            machine[k.strip()] = v.strip()
except FileNotFoundError:
    pass
cores = int(machine.get("cores", "3") or 3)

rows = list(csv.DictReader(open(os.path.join(out, "samples.csv"))))
by_time = defaultdict(list)
for r in rows:
    by_time[int(r["t"])].append(r)
times = sorted(by_time)

last = {}          # pid -> cputime seconds
seen_first = set(r["pid"] for r in by_time[times[0]]) if times else set()
for r in by_time[times[0]] if times else []:
    last[r["pid"]] = seconds(r["cputime"])

intervals = []     # (t, phase, total_core_pct, {name: core_pct})
for prev, t in zip(times, times[1:]):
    dt = t - prev
    if dt <= 0:
        continue
    per = defaultdict(float)
    phase = by_time[t][0]["phase"] if by_time[t] else ""
    for r in by_time[t]:
        cpu = seconds(r["cputime"])
        before = last.get(r["pid"], 0.0)
        delta = max(0.0, cpu - before)
        last[r["pid"]] = cpu
        per[label(r["command"])] += delta / dt * 100
    intervals.append((t, phase, sum(per.values()), dict(per)))

with open(os.path.join(out, "intervals.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["t_seconds", "phase", "agent_pct_of_one_core", "agent_pct_of_machine"])
    for t, ph, total, _ in intervals:
        w.writerow([t, ph, round(total, 2), round(total / cores, 2)])


def p(values, q):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def minute_peak(items):
    # Highest 60-second average, to separate a sustained load from a 5-second blip.
    best = 0.0
    for i in range(len(items)):
        window = [x for x in items[i:] if x[0] - items[i][0] < 60]
        if len(window) >= 6:
            best = max(best, statistics.mean(v for _, v in window))
    return best


lines = []
lines.append(f"## Agent CPU: `{machine.get('config', '?')}`")
lines.append("")
lines.append(f"Machine: {machine.get('cpu', '?')}, {cores} cores, {machine.get('memory_gb', '?')} GB, "
             f"macOS {machine.get('ProductVersion', '?')}. Sampled every 5 s.")
lines.append("")
lines.append("| Phase | Minutes | Average, % of machine | 95th pct, % of machine | Highest 1-min, % of machine | Highest 5 s, % of one core |")
lines.append("|---|---|---|---|---|---|")
phase_names = {"start": "Start (just installed)", "steady": "Steady (running in background)",
               "rescan": "Restart with full file scan"}
for ph in ["start", "steady", "rescan", "all"]:
    sel = [(t, v) for t, x, v, _ in intervals if ph == "all" or x == ph]
    if not sel:
        continue
    vals = [v for _, v in sel]
    mins = (sel[-1][0] - sel[0][0]) / 60 if len(sel) > 1 else 0
    lines.append(f"| {phase_names.get(ph, 'Whole run')} | {mins:.0f} | {statistics.mean(vals) / cores:.2f}% | "
                 f"{p(vals, 0.95) / cores:.2f}% | {minute_peak(sel) / cores:.2f}% | {max(vals):.1f}% |")
lines.append("")

totals = defaultdict(float)
for _, _, _, per in intervals:
    for k, v in per.items():
        totals[k] += v
n = max(1, len(intervals))
lines.append("Average by process over the whole run (% of one core):")
lines.append("")
for k, v in sorted(totals.items(), key=lambda kv: -kv[1])[:8]:
    lines.append(f"- {k}: {v / n:.2f}%")
lines.append("")

try:
    log = open(os.path.join(out, "key-log-lines.txt")).read()
    scans = len(re.findall(r"scan ended", log))
    lines.append(f"File scans completed (from the agent's own log): {scans}.")
    errors = [l for l in log.splitlines() if "ERROR" in l or "CRITICAL" in l]
    if errors:
        lines.append(f"Agent log errors: {len(errors)} (first: `{errors[0][:160]}`).")
except FileNotFoundError:
    pass

summary = "\n".join(lines) + "\n"
open(os.path.join(out, "summary.md"), "w").write(summary)
print(summary)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot([t / 60 for t, *_ in intervals], [v / cores for _, _, v, _ in intervals], linewidth=0.8)
    ax.set_xlabel("minutes")
    ax.set_ylabel("agent CPU, % of machine")
    ax.set_title(f"Wazuh agent CPU ({machine.get('config', '?')}) on {machine.get('cpu', '?')}")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cpu.png"), dpi=120)
except Exception as exc:  # the chart is a nice-to-have
    print(f"(no chart: {exc})")

"""
benchmark.py
------------
Measures and compares the scan-time performance of three YARA rule types:
hexadecimal string matching, regular expression matching, and plain text
string matching. Designed for a JEI research submission.

Run generate_dataset.py first to create the test files, then run this.
Results land in the results/ folder as CSV files ready for graphing.

Requires: yara-python, psutil
Optional: scipy (needed for proper t-distribution CI; falls back to z=1.96 without it)
"""

import os
import sys
import time
import csv
import statistics
import threading
import platform
import datetime

try:
    import yara
except ImportError:
    sys.exit("yara-python isn't installed. Run: pip install yara-python")

try:
    import psutil
except ImportError:
    sys.exit("psutil isn't installed. Run: pip install psutil")

try:
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


# Change these if you move folders around
DATASET_DIR   = "dataset"
RULES_DIR     = "rules"
OUTPUT_DIR    = "results"

NUM_TRIALS    = 100   # how many real recorded trials per rule type
WARMUP_TRIALS = 5     # throws these away before recording starts
MIN_BYTES     = 1
MAX_BYTES     = 10_000_000   # skip anything over 10 MB, shouldn't happen but just in case
OUTLIER_SD    = 3.0   # trials this many standard deviations out get flagged
CONFIDENCE    = 0.95

RULE_FILES = {
    "Hex":   os.path.join(RULES_DIR, "hex_rule.yar"),
    "Regex": os.path.join(RULES_DIR, "regex_rule.yar"),
    "Text":  os.path.join(RULES_DIR, "text_rule.yar"),
}


def load_files_into_memory(directory, min_bytes=MIN_BYTES, max_bytes=MAX_BYTES):
    # Loading everything into RAM before the benchmark starts is important.
    # If we read from disk during each trial, we're measuring disk speed as much
    # as YARA performance, which isn't what we want to compare here.
    if not os.path.isdir(directory):
        sys.exit(
            f"Couldn't find the dataset folder '{directory}'.\n"
            f"Run generate_dataset.py first to create it."
        )

    file_data = []
    skipped = 0
    for fname in sorted(os.listdir(directory)):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        size = os.path.getsize(fpath)
        if not (min_bytes <= size <= max_bytes):
            skipped += 1
            continue
        with open(fpath, "rb") as f:
            file_data.append((fname, f.read()))

    if not file_data:
        sys.exit(f"No valid files found in '{directory}'.")

    total_mb = sum(len(d) for _, d in file_data) / (1024 * 1024)
    print(f"Loaded {len(file_data)} files into memory ({total_mb:.1f} MB) — {skipped} skipped")
    return file_data


def compile_rules(rule_files):
    # Rules get compiled once here, before any timing starts. Compilation
    # converts the .yar text into YARA's internal binary format. Mixing
    # compile time into the scan timing would contaminate the results.
    compiled = {}
    for name, path in rule_files.items():
        if not os.path.isfile(path):
            sys.exit(f"Rule file not found: {path}")
        compiled[name] = yara.compile(filepath=path)
        print(f"  Compiled {name} <- {path}")
    return compiled


class ResourceMonitor:
    # Runs a background thread that samples CPU% and RSS memory every 5ms.
    # We record the peak of each, not an average, because a spike that only
    # lasts 10ms still represents real overhead that matters in production.
    #
    # One gotcha: psutil's cpu_percent() returns 0.0 on the very first call
    # because it needs two measurements to calculate a delta. Calling it once
    # in __init__ primes the counter so the first real reading is accurate.

    POLL_INTERVAL = 0.005

    def __init__(self):
        self._proc = psutil.Process(os.getpid())
        self._peak_cpu = 0.0
        self._peak_mem = 0
        self._active = False
        self._thread = None
        self._proc.cpu_percent(interval=None)  # prime the counter

    def _poll(self):
        while self._active:
            try:
                cpu = self._proc.cpu_percent(interval=None)
                mem = self._proc.memory_info().rss
                if cpu > self._peak_cpu:
                    self._peak_cpu = cpu
                if mem > self._peak_mem:
                    self._peak_mem = mem
            except psutil.NoSuchProcess:
                break
            time.sleep(self.POLL_INTERVAL)

    def start(self):
        self._peak_cpu = 0.0
        self._peak_mem = 0
        self._active = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def stop(self):
        # Returns (peak_cpu_pct, peak_rss_mb)
        self._active = False
        if self._thread:
            self._thread.join(timeout=1.0)
        return self._peak_cpu, self._peak_mem / (1024 * 1024)


def scan_dataset(compiled_rule, file_data, monitor):
    # perf_counter_ns() gives nanosecond resolution tied to the CPU clock.
    # time.time() rounds to ~15ms on Windows which would make fast hex scans
    # look identical when they actually differ — hence the high-res counter.
    monitor.start()
    t0 = time.perf_counter_ns()

    for _fname, data in file_data:
        try:
            compiled_rule.match(data=data)
        except yara.Error:
            pass  # malformed buffer, just skip it

    t1 = time.perf_counter_ns()
    peak_cpu, peak_mem = monitor.stop()

    return (t1 - t0), peak_cpu, peak_mem


def _draw_progress(done, total, width=40):
    filled = int(width * done / total)
    bar = "=" * filled + "-" * (width - filled)
    pct = done / total * 100
    print(f"\r  [{bar}] {pct:5.1f}%  ({done}/{total})", end="", flush=True)


def run_benchmark(compiled_rules, file_data, num_trials=NUM_TRIALS, warmup=WARMUP_TRIALS):
    rule_names = list(compiled_rules.keys())
    monitor = ResourceMonitor()

    # Warm-up passes: the first few scans are always slower because Python's
    # interpreter is JIT-warming and the OS file cache is cold. Running a few
    # throwaway passes levels the playing field before we start recording.
    print(f"\nRunning {warmup} warm-up passes (results discarded)...")
    for w in range(warmup):
        for name in rule_names:
            scan_dataset(compiled_rules[name], file_data, monitor)
        _draw_progress(w + 1, warmup)
    print()

    results = {
        name: {"times_ms": [], "cpu_peaks": [], "mem_peaks_mb": []}
        for name in rule_names
    }

    total_scans = num_trials * len(rule_names)
    done = 0

    print(f"\nRunning {num_trials} trials x {len(rule_names)} rule types = {total_scans} total scans...")

    # Interleaving the rule types on every trial (Hex, Regex, Text, Hex, Regex, Text...)
    # rather than doing all 100 Hex trials first is intentional. If we ran one rule
    # type all at once, later rule types would benefit from files already sitting in
    # the OS page cache and look artificially faster. This way caching bias is spread
    # evenly across all three rule types.
    for _trial in range(num_trials):
        for name in rule_names:
            elapsed_ns, peak_cpu, peak_mem = scan_dataset(
                compiled_rules[name], file_data, monitor
            )
            results[name]["times_ms"].append(elapsed_ns / 1_000_000)
            results[name]["cpu_peaks"].append(peak_cpu)
            results[name]["mem_peaks_mb"].append(peak_mem)

            done += 1
            _draw_progress(done, total_scans)

    print()
    return results


def _ci_halfwidth(data, confidence=CONFIDENCE):
    n = len(data)
    if n < 2:
        return 0.0
    std = statistics.stdev(data)
    if HAS_SCIPY:
        # t-distribution is correct here because n=100 is large but not infinite
        t_crit = scipy_stats.t.ppf((1 + confidence) / 2, df=n - 1)
    else:
        t_crit = 1.96  # z-score fallback, fine for n=100
    return t_crit * std / (n ** 0.5)


def detect_outliers(data, threshold=OUTLIER_SD):
    # Flag anything more than 3 SD from the mean. This catches trials where
    # something like a Windows Defender scan or system update briefly spiked
    # CPU in the background. Those trials are logged but excluded from stats.
    if len(data) < 4:
        return data, []
    mean = statistics.mean(data)
    std = statistics.stdev(data)
    if std == 0:
        return data, []
    outlier_idx = [i for i, v in enumerate(data) if abs(v - mean) > threshold * std]
    clean = [v for i, v in enumerate(data) if i not in set(outlier_idx)]
    return clean, outlier_idx


def aggregate(data_list):
    clean, outliers = detect_outliers(data_list)
    n = len(clean)
    mean = statistics.mean(clean)
    std = statistics.stdev(clean) if n > 1 else 0.0
    ci = _ci_halfwidth(clean)
    return {
        "n":           n,
        "mean":        mean,
        "std":         std,
        "ci":          ci,
        "min":         min(clean),
        "max":         max(clean),
        "median":      statistics.median(clean),
        "outliers":    outliers,
        "n_outliers":  len(outliers),
        "raw_n":       len(data_list),
    }


def run_ttests(results):
    # Welch's t-test rather than Student's because we can't assume the three
    # rule types have equal variance — that assumption would likely be violated
    # given how different regex and hex timing distributions look in practice.
    if not HAS_SCIPY:
        return {}

    names = list(results.keys())
    ttests = {}
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            t_stat, p = scipy_stats.ttest_ind(
                results[a]["times_ms"],
                results[b]["times_ms"],
                equal_var=False
            )
            ttests[f"{a}_vs_{b}"] = {
                "t":           round(t_stat, 4),
                "p":           round(p, 6),
                "significant": p < 0.05,
            }
    return ttests


def print_summary(stats, ttests):
    W = 68
    print("\n" + "=" * W)
    print(f"{'RESULTS SUMMARY':^{W}}")
    print("=" * W)

    header = (f"{'Rule':<8} {'Mean ms':>9} {'SD':>8} "
              f"{'95% CI':>9} {'Median':>9} {'Outliers':>9}")
    print(header)
    print("-" * W)

    for name, s in stats.items():
        t = s["time"]
        print(
            f"{name:<8} {t['mean']:>9.3f} {t['std']:>8.3f} "
            f"+/-{t['ci']:>7.3f} {t['median']:>9.3f} "
            f"{t['n_outliers']:>5}/{t['raw_n']}"
        )

    print("=" * W)

    if "Regex" in stats:
        regex_mean = stats["Regex"]["time"]["mean"]
        print("  Speed relative to Regex:")
        for name, s in stats.items():
            ratio = regex_mean / s["time"]["mean"]
            direction = "faster" if ratio > 1 else "slower"
            print(f"    {name:<8}  {ratio:5.2f}x  {direction}")

    if ttests:
        print("-" * W)
        print("  Welch's t-test (p < 0.05 = statistically significant):")
        for pair, r in ttests.items():
            sig = "yes" if r["significant"] else "no"
            print(f"    {pair:<20}  t={r['t']:>8.3f}  p={r['p']:.6f}  significant={sig}")
    elif not HAS_SCIPY:
        print("  Note: scipy not installed, t-tests skipped. Run: pip install scipy")

    print("=" * W + "\n")


def export_summary_csv(stats, ttests, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "summary_stats.csv")

    fields = [
        "rule_type", "n_trials", "n_outliers_removed",
        "mean_time_ms", "std_time_ms", "ci95_time_ms",
        "min_time_ms", "max_time_ms", "median_time_ms",
        "mean_cpu_pct", "std_cpu_pct",
        "mean_mem_mb", "std_mem_mb",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for name, s in stats.items():
            w.writerow({
                "rule_type":          name,
                "n_trials":           s["time"]["n"],
                "n_outliers_removed": s["time"]["n_outliers"],
                "mean_time_ms":       round(s["time"]["mean"],   4),
                "std_time_ms":        round(s["time"]["std"],    4),
                "ci95_time_ms":       round(s["time"]["ci"],     4),
                "min_time_ms":        round(s["time"]["min"],    4),
                "max_time_ms":        round(s["time"]["max"],    4),
                "median_time_ms":     round(s["time"]["median"], 4),
                "mean_cpu_pct":       round(s["cpu"]["mean"],    4),
                "std_cpu_pct":        round(s["cpu"]["std"],     4),
                "mean_mem_mb":        round(s["mem"]["mean"],    4),
                "std_mem_mb":         round(s["mem"]["std"],     4),
            })
    print(f"  summary_stats.csv  -> {path}")

    if ttests:
        tpath = os.path.join(out_dir, "ttest_results.csv")
        with open(tpath, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["comparison", "t_statistic", "p_value", "significant_p05"])
            w.writeheader()
            for pair, r in ttests.items():
                w.writerow({
                    "comparison":      pair,
                    "t_statistic":     r["t"],
                    "p_value":         r["p"],
                    "significant_p05": r["significant"],
                })
        print(f"  ttest_results.csv  -> {tpath}")


def export_raw_csv(results, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "raw_trials.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trial", "rule_type", "time_ms", "peak_cpu_pct", "peak_mem_mb"])
        for name, data in results.items():
            for i, (t, c, m) in enumerate(
                zip(data["times_ms"], data["cpu_peaks"], data["mem_peaks_mb"]), 1
            ):
                w.writerow([i, name, round(t, 4), round(c, 4), round(m, 4)])
    print(f"  raw_trials.csv     -> {path}")


def export_run_info(stats, out_dir):
    # Saves hardware and software environment details so the experiment can
    # be reproduced on a different machine and any hardware differences noted.
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "run_info.txt")
    with open(path, "w") as f:
        f.write("YARA Benchmark - Run Info\n")
        f.write("-" * 40 + "\n")
        f.write(f"Timestamp : {datetime.datetime.now().isoformat()}\n")
        f.write(f"Python    : {sys.version}\n")
        f.write(f"Platform  : {platform.platform()}\n")
        f.write(f"CPU       : {platform.processor()}\n")
        f.write(f"Cores     : {psutil.cpu_count(logical=True)} logical, "
                f"{psutil.cpu_count(logical=False)} physical\n")
        mem_gb = psutil.virtual_memory().total / (1024 ** 3)
        f.write(f"RAM       : {mem_gb:.1f} GB\n")
        f.write(f"Trials    : {NUM_TRIALS} recorded + {WARMUP_TRIALS} warm-up (discarded)\n")
        f.write(f"scipy     : {'yes' if HAS_SCIPY else 'no (z=1.96 fallback used)'}\n")
        f.write("\nOutlier report:\n")
        for name, s in stats.items():
            f.write(f"  {name}: {s['time']['n_outliers']} removed from {s['time']['raw_n']} trials\n")
            if s["time"]["outliers"]:
                f.write(f"    Indices: {s['time']['outliers']}\n")
    print(f"  run_info.txt       -> {path}")


def main():
    print("\nYARA Performance Benchmark")
    print("-" * 30)

    if not HAS_SCIPY:
        print(
            "Warning: scipy not found. CI will use z=1.96 instead of t-distribution, "
            "and Welch's t-tests will be skipped.\n"
            "Install it with: pip install scipy\n"
        )

    file_data = load_files_into_memory(DATASET_DIR)
    compiled_rules = compile_rules(RULE_FILES)
    results = run_benchmark(compiled_rules, file_data)

    stats = {}
    for name, data in results.items():
        stats[name] = {
            "time": aggregate(data["times_ms"]),
            "cpu":  aggregate(data["cpu_peaks"]),
            "mem":  aggregate(data["mem_peaks_mb"]),
        }

    ttests = run_ttests(results)
    print_summary(stats, ttests)

    print("Exporting results...")
    export_summary_csv(stats, ttests, OUTPUT_DIR)
    export_raw_csv(results, OUTPUT_DIR)
    export_run_info(stats, OUTPUT_DIR)

    print("\nDone. Check the results/ folder for your CSV files.")


if __name__ == "__main__":
    main()
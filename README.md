# YARA Benchmark

Code for the paper *"Evaluating computational efficiency in YARA: regex vs hexadecimal string matching performance"*.

---

## What you need

- Python 3.9 or newer
- pip (comes with Python)

---

## Setup

Open a terminal in this folder, then install the two dependencies:

```bash
pip install -r requirements.txt
```

This pulls in `yara-python` (the YARA engine wrapper) and `psutil` (for CPU and memory readings during scans). Optionally install `scipy` too for proper t-distribution confidence intervals and Welch's t-tests — the script works without it but will warn you.

```bash
pip install scipy
```

> **Windows note:** `yara-python` needs a C compiler to build. If pip fails, install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) first, or use conda: `conda install -c conda-forge yara-python`

---

## Running the experiment

**Step 1 — generate the test files**

```bash
python generate_dataset.py 
or
python3 generate_dataset.py 
```

Creates a `dataset/` folder with 1,000 synthetic files: a mix of fake PE executables, shell scripts, ZIPs, PDFs, C2-style config files, and plain text. Takes about 5 seconds.

**Step 2 — run the benchmark**

```bash
python benchmark.py
or
python3 benchmark.py
```

Runs 100 trials per rule type (300 total scans), with 5 warm-up passes discarded before recording starts. Progress prints to the screen. Expect 5–15 minutes depending on your hardware.

---

## Results

When it finishes, open the `results/` folder:

- **`summary_stats.csv`** — mean, standard deviation, 95% CI, min, max, and median scan time for each rule type, plus CPU and memory peaks. This is the source for the paper's data table and bar charts.
- **`raw_trials.csv`** — every individual trial. Use this for scatter plots or to check that timing distributions look reasonable.
- **`ttest_results.csv`** — Welch's t-test output for each rule-type pair. Only generated if scipy is installed.
- **`run_info.txt`** — hardware specs and timestamp logged at the time of the run, for the Methods section.

### Building the charts

1. Open `summary_stats.csv` in Google Sheets or Excel
2. Select `rule_type` and `mean_time_ms` → insert a bar chart (Figure 1). Add error bars from `ci95_time_ms`.
3. Repeat with `mean_cpu_pct` for the CPU utilization chart (Figure 2)
4. Open `raw_trials.csv`, filter by rule type, and plot a line chart across all 100 trials to show consistency over time (Figure 3)

---

## File layout

```
├── benchmark.py          — main benchmark script (run second)
├── generate_dataset.py   — creates the test files (run first)
├── requirements.txt
├── README.md
├── rules/
│   ├── hex_rule.yar
│   ├── regex_rule.yar
│   └── text_rule.yar
├── dataset/              — created by generate_dataset.py
└── results/              — created by benchmark.py
```

---

## Reproducing this experiment

The dataset generator uses a fixed seed (`SEED = 42`), so `generate_dataset.py` always produces the same 1,000 files in the same order. Clone the repo, run both scripts, and you get identical experimental conditions to the original run.

# 🔒 Shai-Halud Dependency Scanner

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A **security scanner for Node.js projects** that detects **infected dependencies** from the **Shai-Halud npm supply-chain attack (2025)**.  
It works across major package managers and lockfiles:

- ✅ **npm** (`package-lock.json`)  
- ✅ **pnpm** (`pnpm-lock.yaml`)  
- ✅ **Yarn v1 & v2** (`yarn.lock`)  
- 🔄 CLI fallback (`npm ls`, `pnpm list`, `yarn list`)  

> 🚨 This tool is designed for developers, CI/CD pipelines, and security teams who need to quickly **check if their project is compromised**.

---

## ✨ Features

- Detects **compromised npm packages** by name & version.
- Works with **lockfiles** (preferred) for static analysis — **no install required**.
- Falls back to **safe CLI inspection** if no lockfile is present.
- Outputs **human-readable tables** or **JSON reports** (machine-friendly for CI).
- Fast, dependency-free (uses Python standard library; `pyyaml` optional).
- 🚀 Zero-risk: never modifies your project or installs dependencies.

---

## 📦 Installation

Clone the repo and run the script directly:

```bash
git clone https://github.com/sergfa/cross-package-manager.git
cd cross-package-manager
python3 scan_shai_halud.py --help
```

(Or add it as a Git submodule in your monorepo’s security tooling.)

---

## 🔍 Usage

### Quick scan (table output)
```bash
python scan_shai_halud.py --csv affected.csv --format table
```

### JSON report (for CI/CD pipelines)
```bash
python scan_shai_halud.py --csv affected.csv --dir ../my-repo --format json --output report.json
```

### Command-line options

| Argument      | Description |
|---------------|-------------|
| `--csv`       | **(required)** Path to the affected packages CSV file |
| `--dir`       | Project root to scan (default: `.`) |
| `--format`    | Output format: `table` (default) or `json` |
| `--output`    | Write report to file instead of stdout |
| `--max-depth` | Limit recursion depth for CLI fallback commands |
| `--verbose`   | Print diagnostics about detection strategy and fallbacks |

---

## 🛑 Exit Codes

- `0` – ✅ Safe: no flagged packages detected  
- `2` – ⚠️ Warning: one or more flagged packages detected (CI should fail)  
- `1` – ❌ Error: CSV unreadable, lockfile parse error, or CLI error  

---

## 🧪 Tests & Fixtures

The repo includes minimal **lockfile fixtures** and a sample `affected.csv`.  
Run unit tests with:

```bash
python -m unittest discover tests
```

---


## 🤝 Contributing

Pull requests are welcome!  
- Add support for additional lockfile formats (e.g., Bun).  
- Improve detection logic.  
- Submit fixes for new edge cases.  

---

## 📢 Spread the word

If you find this useful, please **⭐ star the repo** and share it with your team to help protect more developers from the **Shai-Halud malware**.

---

## 📜 License

MIT License © 2025 – Contributions welcome!

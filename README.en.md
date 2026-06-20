<div align="center">

[![License: MIT](https://img.shields.io/github/license/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/releases)
[![Stars](https://img.shields.io/github/stars/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/stargazers)

<p align="center">
  <img src="docs/assets/logo.png" alt="SidecarPatcher logo" width="160"/>
</p>

<h1 id="readme-top" align="center">SidecarPatcher</h1>

<p align="center">Experimental prototype to re-enable Sidecar on unsupported Mac and iPad hardware.</p>

<p align="center">🇬🇧 <a href="README.en.md"><b>English</b></a> · 🇫🇷 <a href="README.md">Français</a></p>

</div>

---

## What is this?

SidecarPatcher is a Python script that modifies Apple's `SidecarCore` binary to bypass the hardware compatibility check for Sidecar. It automatically locates the relevant function via a binary signature and applies an assembly-level patch.

> ⚠️ **Prototype** — the modified binary cannot be properly code-signed under macOS Sequoia. This project is a technical exploration, not a turnkey solution.

---

## How I got here

I'm not a developer by training and I'm new to Python. This project started from a conversation with an AI: I wanted to re-enable Sidecar on my Mac and iPad Air 2, and decided to dig in.

I learned on the fly — ARM64 assembly, DYLD cache extraction, Hopper Disassembler for binary analysis, code signing and entitlements. I spent many hours understanding how macOS locks down its frameworks and what it means to modify them.

The full research journal (everything is explained there): [`docs/RECHERCHE.md`](docs/RECHERCHE.md).

---

## Stack

- [![Python](https://img.shields.io/badge/python-3670A0?style=flat&logo=python&logoColor=ffdd54)](https://www.python.org/) — stdlib only (`argparse`, `pathlib`, `dataclasses`)
- [Hopper Disassembler](https://www.hopperapp.com/) — ARM64 binary analysis
- [`dyld-shared-cache-extractor`](https://github.com/keith/dyld-shared-cache-extractor) — framework cache extraction

---

## Quick Start

```bash
git clone https://github.com/Sofian-bll/SidecarPatcher.git
cd SidecarPatcher
python3 sidecar_patcher.py /path/to/SidecarCore
```

The script scans the binary, locates the signature, and writes the patched file (`SidecarCore.patched`).

---

## Usage

```bash
# Basic patch (automatic signature detection)
python3 sidecar_patcher.py SidecarCore

# Manual offset (decimal or hex)
python3 sidecar_patcher.py SidecarCore --force-offset 0x3A2C

# Custom output file
python3 sidecar_patcher.py SidecarCore -o /tmp/SidecarCore.patched

# Disable automatic backup
python3 sidecar_patcher.py SidecarCore --no-backup

# Adjust NOP padding
python3 sidecar_patcher.py SidecarCore --nop-count 5
```

---

## Current Status

- [x] `SidecarCore` binary extraction from DYLD cache
- [x] Compatibility function identified via Hopper
- [x] Automated binary patching (signature + NOP padding)
- [ ] Modified binary code signing under macOS Sequoia

---

## Files

| File/Folder | Description |
|-------------|-------------|
| `sidecar_patcher.py` | Main patching script |
| `docs/RECHERCHE.md` | Full research journal |
| `docs/INSTALLATION.md` | Setup guide and prerequisites |
| `docs/COMMANDES.md` | Command reference |

---

## Alternatives

For a working solution without binary code signing:

- [**FeatureUnlock**](https://github.com/acidanthera/FeatureUnlock) — Lilu kext enabling Sidecar, NightShift, AirPlay at the kernel level (requires OpenCore)
- [**free-sidecar**](https://github.com/ben-z/free-sidecar) — similar binary patching approach

---

## License

MIT © 2026 Sofian — see [LICENSE](LICENSE).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- REFERENCE_LINKS -->

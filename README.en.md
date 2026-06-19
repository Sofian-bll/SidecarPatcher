> [Lire en Francais](README.md) | [Read in English](README.en.md)

<p align="center">
  <img src="assets/logo.svg" alt="SidecarPatcher logo" width="160"/>
</p>

<h1 align="center" id="readme-top">SidecarPatcher</h1>
 
<p align="center">
  Experimental prototype to re-enable Sidecar on unsupported Mac and iPad hardware.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat" alt="License"/>
  <img src="https://img.shields.io/badge/Python-3-blue?style=flat&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/macOS-Sequoia-000000?style=flat&logo=apple" alt="macOS"/>
</p>

---

## What is this?

SidecarPatcher is an attempt to re-enable the Sidecar feature on Apple hardware too old for official support. The Python script locates and modifies the compatibility check function in the `SidecarCore` binary, but the modified binary's code signature remains unresolved — this is a prototype, not a turnkey solution.

## Current Status

- ✅ `SidecarCore` binary extraction
- ✅ Compatibility function identified via Hopper
- ❌ Modified binary code signing

For a working solution, see [FeatureUnlock](https://github.com/acidanthera/FeatureUnlock) or [free-sidecar](https://github.com/ben-z/free-sidecar).

## Structure

| File/Folder | Description |
|-------------|-------------|
| `sidecar_patcher.py` | Main patching script |
| `docs/RECHERCHE.md` | Research journal and technical notes |
| `docs/INSTALLATION.md` | Setup guide and prerequisites |
| `docs/COMMANDES.md` | Command reference |

## License

MIT © 2026 Sofian — see [LICENSE](LICENSE).

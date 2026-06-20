<div align="center">

[![Licence : MIT](https://img.shields.io/github/license/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/blob/main/LICENSE)
[![Version](https://img.shields.io/github/v/release/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/releases)
[![Stars](https://img.shields.io/github/stars/Sofian-bll/SidecarPatcher?style=flat)](https://github.com/Sofian-bll/SidecarPatcher/stargazers)

<p align="center">
  <img src="docs/assets/logo.png" alt="SidecarPatcher logo" width="160"/>
</p>

<h1 id="readme-top" align="center">SidecarPatcher</h1>

<p align="center">Prototype experimental de reactivation de Sidecar sur Mac et iPad non supportes.</p>

<p align="center">🇬🇧 <a href="README.en.md">English</a> · 🇫🇷 <a href="README.md"><b>Français</b></a></p>

</div>

---

## C'est quoi ?

SidecarPatcher est un script Python qui modifie le binaire `SidecarCore` d'Apple pour contourner la verification de compatibilite materielle de Sidecar. Il localise automatiquement la fonction responsable via une signature binaire et y applique un patch assembleur.

> ⚠️ **Prototype** — le binaire modifie n'est pas signe correctement sous macOS Sequoia. Ce projet est une exploration technique, pas une solution cle en main.

---

## Comment j'en suis arrive la

Je ne suis pas developpeur de formation et je debute en Python. Ce projet est ne d'une discussion avec une IA : je voulais reactiver Sidecar sur mon Mac et mon iPad Air 2, et j'ai decide de creuser.

J'ai appris sur le tas — assembleur ARM64, extraction du cache DYLD, Hopper Disassembler pour analyser le binaire, signature de code et entitlements. J'ai passe pas mal d'heures a comprendre comment macOS verrouille ses frameworks, et ce que ca implique de les modifier.

Le journal de recherche complet (tout y est explique) : [`docs/RECHERCHE.md`](docs/RECHERCHE.md).

---

## Stack

- [![Python](https://img.shields.io/badge/python-3670A0?style=flat&logo=python&logoColor=ffdd54)](https://www.python.org/) — stdlib uniquement (`argparse`, `pathlib`, `dataclasses`)
- [Hopper Disassembler](https://www.hopperapp.com/) — analyse du binaire ARM64
- [`dyld-shared-cache-extractor`](https://github.com/keith/dyld-shared-cache-extractor) — extraction du cache framework

---

## Quick Start

```bash
git clone https://github.com/Sofian-bll/SidecarPatcher.git
cd SidecarPatcher
python3 sidecar_patcher.py /chemin/vers/SidecarCore
```

Le script scanne le binaire, trouve la signature et ecrit le fichier patche (`SidecarCore.patched`).

---

## Usage

```bash
# Patch basique (detection automatique de la signature)
python3 sidecar_patcher.py SidecarCore

# Offset manuel (decimal ou hexa)
python3 sidecar_patcher.py SidecarCore --force-offset 0x3A2C

# Fichier de sortie personnalise
python3 sidecar_patcher.py SidecarCore -o /tmp/SidecarCore.patched

# Desactiver la sauvegarde automatique
python3 sidecar_patcher.py SidecarCore --no-backup

# Ajuster le padding NOP
python3 sidecar_patcher.py SidecarCore --nop-count 5
```

---

## Etat actuel

- [x] Extraction du binaire `SidecarCore` depuis le cache DYLD
- [x] Identification de la fonction de compatibilite via Hopper
- [x] Patch binaire automatise (signature + NOP padding)
- [ ] Signature du binaire modifie sous macOS Sequoia

---

## Fichiers

| Fichier/Dossier | Description |
|-----------------|-------------|
| `sidecar_patcher.py` | Script de patch principal |
| `docs/RECHERCHE.md` | Journal de recherche complet |
| `docs/INSTALLATION.md` | Guide d'installation et prerequis |
| `docs/COMMANDES.md` | Aide-memoire des commandes utiles |

---

## Alternatives

Pour une solution fonctionnelle sans signature de binaire :

- [**FeatureUnlock**](https://github.com/acidanthera/FeatureUnlock) — kext Lilu qui active Sidecar, NightShift, AirPlay au niveau noyau (necessite OpenCore)
- [**free-sidecar**](https://github.com/ben-z/free-sidecar) — approche similaire de patch binaire

---

## Licence

MIT © 2026 Sofian — voir [LICENSE](LICENSE).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- REFERENCE_LINKS -->

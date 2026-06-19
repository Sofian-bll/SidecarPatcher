> [Lire en Francais](README.md) | [Read in English](README.en.md)

<p align="center">
  <img src="assets/logo.svg" alt="SidecarPatcher logo" width="160"/>
</p>

<h1 align="center" id="readme-top">SidecarPatcher</h1>

<p align="center">
  Prototype experimental de reactivation de Sidecar sur Mac et iPad non supportes.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat" alt="License"/>
  <img src="https://img.shields.io/badge/Python-3-blue?style=flat&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/macOS-Sequoia-000000?style=flat&logo=apple" alt="macOS"/>
</p>

---

## C'est quoi ?

SidecarPatcher est une tentative de reactiver la fonction Sidecar sur du materiel Apple trop ancien pour etre officiellement pris en charge. Le script Python repere et modifie la fonction de verification de compatibilite dans le binaire `SidecarCore`, mais la signature du binaire modifie reste non resolue — le projet est un prototype, pas une solution cle en main.

## Etat actuel

- ✅ Extraction du binaire `SidecarCore`
- ✅ Identification de la fonction de compatibilite via Hopper
- ❌ Signature du binaire modifie

Pour une solution fonctionnelle, voir [FeatureUnlock](https://github.com/acidanthera/FeatureUnlock) ou [free-sidecar](https://github.com/ben-z/free-sidecar).

## Structure

| Fichier/Dossier | Description |
|-----------------|-------------|
| `sidecar_patcher.py` | Script de patch principal |
| `docs/RECHERCHE.md` | Journal de recherche et explications techniques |
| `docs/INSTALLATION.md` | Guide et prerequis |
| `docs/COMMANDES.md` | Aide-memoire des commandes |

## Licence

MIT © 2026 Sofian — voir [LICENSE](LICENSE).

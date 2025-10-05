# SidecarPatcher

SidecarPatcher est un utilitaire en ligne de commande qui applique un patch binaire
minimaliste au framework macOS **SidecarCore** afin de désactiver la vérification de
compatibilité côté appareil. Le projet a été nettoyé pour ne contenir que le code
nécessaire au patch, sans binaires compilés ni artefacts temporaires.

## Fonctionnalités

- Recherche automatique de la signature machine de la fonction
  `SidecarDisplayIsSupportedReceivingDevice`.
- Application d'un patch `MOV EAX, 1; RET` et remplissage optionnel avec des NOP.
- Sauvegarde automatique du fichier original avant modification.
- Possibilité de forcer un offset ou un nombre de NOP personnalisé.

## Installation

Le script ne dépend d'aucune bibliothèque externe. Il suffit de disposer d'une
installation Python 3.9 ou plus récente.

## Utilisation

```bash
python sidecar_patcher.py /chemin/vers/SidecarCore -o SidecarCore.patched
```

Options disponibles :

- `-o/--output PATH` : chemin du fichier patché (par défaut `SidecarCore.patched`).
- `--no-backup` : n'enregistre pas de sauvegarde lorsque le patch est appliqué en place.
- `--force-offset OFFSET` : offset du patch (en décimal ou hexadécimal `0x...`).
- `--nop-count N` : nombre de NOP à insérer après le patch (par défaut 10).

## Restaurer un binaire sauvegardé

Si vous patchez le binaire sur place, une sauvegarde `SidecarCore.bak` est créée.
Pour la restaurer :

```bash
cp SidecarCore.bak SidecarCore
```

## Licence

Ce projet est distribué sous licence MIT. Consultez le fichier `LICENSE` si disponible.

# INSTALLATION — Guide d'installation et d'utilisation

> **Attention** : Ces manipulations sont risquées et peuvent rendre votre système inutilisable. Sauvegardez vos données et procédez avec prudence.

## Pré-requis

- macOS Sequoia 15.6 (ou version comparable).
- Accès administrateur et aisance avec le Terminal.
- Désactivation de System Integrity Protection (SIP) et d'Authenticated Root.
- Outils :
  - Hopper (pour analyser/modifier des binaires)
  - `dyld-shared-cache-extractor` (pour extraire les frameworks du cache DYLD)
  - Xcode Command Line Tools (`xcode-select --install`) ou `ldid` pour tenter de signer le binaire
- Facultatif : OpenCore Legacy Patcher si vous préférez utiliser un kext (FeatureUnlock) plutôt qu'une modification manuelle.

## Sauvegarde et extraction

1. Sauvegarder le framework (si présent) :
```bash
cp /System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore ~/Downloads/SidecarCore.bak
```
> Sur Sequoia, ce fichier est souvent symbolique vers `Versions/Current/SidecarCore`.

2. Désactiver SIP et monter le volume en lecture-écriture :
- Redémarrez en mode récupération (⌘ + R).
- Dans le Terminal de récupération :
```bash
csrutil disable
csrutil authenticated-root disable
reboot
```
- Après redémarrage :
```bash
sudo mount -uw /
```

3. Extraire le cache DYLD (exemple pour `arm64e`) :
```bash
dyld-shared-cache-extractor /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e ~/SidecarCache
```
Le binaire `SidecarCore` se trouvera ensuite dans `~/SidecarCache/System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore`.

## Application du patch (résumé)

1. Copier le binaire extrait :
```bash
cp ~/SidecarCache/System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore ~/SidecarCore.patch
```

2. Lancer le script Python de patch (exemple) :
```bash
python3 sidecar_patcher.py -i ~/SidecarCore.patch -o ~/SidecarCore.patched
```

3. Tenter de signer le binaire :
- Sous macOS Catalina, la commande ad-hoc suivante pouvait suffire :
```bash
sudo codesign -f -s - ~/SidecarCore.patched
```
- Sous Sequoia, cette étape échoue souvent : le framework doit être signé avec un certificat adapté. Des tentatives avec `ldid` et des entitlements personnalisés peuvent être tentées (méthode expérimentale).

4. Remplacement du binaire système (quand signé correctement) :
```bash
sudo cp ~/SidecarCore.patched /System/Library/PrivateFrameworks/SidecarCore.framework/Versions/A/SidecarCore
sudo update_dyld_shared_cache -force
```

5. Réactiver SIP (après avoir terminé et si vous l'aviez désactivé) :
- Redémarrer en récupération et exécuter :
```bash
csrutil enable
csrutil authenticated-root enable
```

## Alternative recommandée : FeatureUnlock

L'équipe Acidanthera propose `FeatureUnlock.kext` (plugin Lilu) qui active Sidecar, NightShift, AirPlay to Mac, Universal Control et Continuity Camera en injectant des correctifs au niveau noyau. Cette solution nécessite OpenCore et peut être plus fiable que la modification manuelle des binaires.

## Liens utiles

- Hopper: https://www.hopperapp.com/  
- dyld-shared-cache-extractor: https://github.com/keith/dyld-shared-cache-extractor  
- ldid: https://github.com/sbingner/ldid  
- OpenCore Legacy Patcher: https://github.com/dortania/OpenCore-Legacy-Patcher
# COMMANDES — Aide-mémoire des commandes utiles

Ce fichier regroupe les commandes utilisées et apprises lors du projet. Elles sont utiles pour explorer le système, monter la partition EFI ou manipuler le cache DYLD.

## Informations système
- `sysctl hw.model` : affiche l'identifiant de modèle du Mac.
- `mdfind "motif"` : recherche via Spotlight (plus rapide que `find`).
- `find / -name "*.plist" 2>/dev/null` : recherche brute sur tout le disque (lent).
- `kmutil showloaded` : liste les extensions noyau chargées.
- `spctl --status` : vérifie si Gatekeeper est activé.
- `sudo spctl --master-disable` : désactive temporairement Gatekeeper.
- `csrutil status` : vérifie l'état de SIP.
- `csrutil disable` / `csrutil enable` : désactive / réactive SIP (en récupération).
- `csrutil authenticated-root disable` : permet de monter le volume système en écriture sur macOS 11+.

## Montage de la partition EFI
- `diskutil list` : affiche les disques et partitions.
- `diskutil mount diskXs1` : monte la partition EFI correspondante (remplace `diskX`).
- `umount /Volumes/EFI` : démonte la partition.

## OpenCore et ProperTree
- `ocvalidate /Volumes/EFI/EFI/OC/config.plist` : vérifie la validité du fichier config d'OpenCore.
- Dans ProperTree:
  - `Clean Snapshot` : désactive les entrées orphelines.
  - `OC Snapshot` : met à jour automatiquement les kexts présents dans `EFI/OC/Kexts`.
  - `Strip Disabled Entries` : supprime les éléments `Enabled=false`.

## DYLD et cache
- Localiser caches DYLD :
```bash
file /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_*
```
- Extraire frameworks du cache :
```bash
dyld-shared-cache-extractor <cache> <destination>
```
- Reconstruire le cache après modification :
```bash
update_dyld_shared_cache -force
```

## Signature et code
- `codesign -f -s - <chemin>` : signe un binaire avec un certificat ad-hoc (fonctionne sous Catalina mais pas toujours sur Sequoia).
- `ldid -Ssidecar_entitlements.plist -M -K devkey.p8 <chemin>` : tentative de signature (méthode expérimentale).

## Divers
- `sudo mount -uw /` : remonte le volume système en écriture.
- `sudo nvram boot-args="amfi_get_out_of_my_way=0x1"` : désactive certaines protections AMFI (utilisé sur Catalina).
- `defaults write com.apple.AppleGVA gvaForceAMDKE -boolean yes` : améliore l'utilisation de l'encodeur vidéo pour Sidecar sur GPU AMD.

## Liens et références rapides
- Exploring macOS private frameworks — https://www.jviotti.com/2023/11/20/exploring-macos-private-frameworks.html
- free-sidecar README — https://raw.githubusercontent.com/ben-z/free-sidecar/master/README.md
- FeatureUnlock README — https://raw.githubusercontent.com/acidanthera/FeatureUnlock/master/README.md
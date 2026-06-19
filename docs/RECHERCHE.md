# RECHERCHE — Journal de recherche

## Objectif initial

L'objectif était d'utiliser Sidecar entre un Mac un peu ancien et un iPad Air 2. Sidecar est une fonctionnalité d'Apple qui permet d'utiliser un iPad comme écran secondaire. Apple désactive cette fonction sur les machines jugées trop anciennes via une "liste noire" intégrée dans `SidecarCore.framework`. L'idée était de modifier le binaire `SidecarCore` pour contourner ces restrictions et permettre à ces appareils d'utiliser l'écran secondaire.

> L'auteur n'étant pas développeur de formation et débutant en Python, il a beaucoup appris en réalisant ce projet et en discutant avec l'IA.

## Comprendre le fonctionnement de Sidecar

- Le binaire qui gère Sidecar est `SidecarCore.framework`.
- Sur macOS Sequoia (15.6), Apple regroupe les frameworks dans un cache partagé (`dyld_shared_cache`) monté sous `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld`.
- Le fichier visible dans Xcode (`.tbd`) n'est qu'un stub ; pour obtenir le vrai binaire il faut extraire le cache (`dyld-shared-cache-extractor`).

## Analyse et patch du binaire

- Avec Hopper Disassembler, l'auteur a parcouru la table des symboles et identifié la fonction de vérification.
- Tentative initiale : modifier `Info.plist` / utiliser `defaults write` — échec car Apple scelle les fichiers système.
- Approach : repérer la fonction qui compare les identifiants et forcer son retour à `true` en modifiant l'assembleur (remplacer la condition par une instruction qui renvoie `1`).
- Reconstruction du binaire et tests.

## Déploiement et obstacles

- Montage du volume système (`sudo mount -uw /`) et remplacement du binaire par la version patchée.
- Problème majeur : la signature du binaire. macOS refuse de charger un framework non signé ou mal signé.
- Les méthodes de signature ad-hoc fonctionnaient sous Catalina mais échouent sous Sequoia. Tentatives avec `ldid` et entitlements personnalisés n'ont pas abouti.
- Alternative envisagée : `FeatureUnlock` (kext Lilu) appliquant le correctif au niveau noyau — nécessite OpenCore, mais contourne le problème de signature.

## Autres essais et apprentissages

- Commandes système utiles : `mdfind`, `find`, `kmutil showloaded`, `spctl`, `csrutil`, etc.
- OpenCore & ProperTree : utilisation pour injecter kexts et créer snapshots.
- Compréhension de l'architecture moderne de macOS : frameworks scellés dans un cache partagé depuis Big Sur — cette évolution complique les modifications traditionnelles.

## Conclusion

Malgré de nombreuses heures de recherche et l'aide de l'IA, l'auteur n'a pas obtenu un binaire `SidecarCore` signé et chargé correctement. La prochaine étape logique serait d'utiliser un plugin Lilu comme `FeatureUnlock` pour appliquer le patch proprement, ou d'attendre une solution plus simple. Néanmoins, ce journal est une ressource utile pour comprendre comment Sidecar est verrouillé et pour explorer macOS en profondeur.
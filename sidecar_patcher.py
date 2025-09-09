#!/usr/bin/env python3
"""
Patch précis pour SidecarDisplayIsSupportedReceivingDevice
Basé sur l'analyse du code assembleur fourni
"""

import os
import shutil
import sys


def find_function_signature(binary_data):
    """
    Cherche la signature exacte de la fonction dans le binaire
    D'après le PDF: push rbp; mov rbp, rsp; push r15; push r14; push r13; push r12; push rbx; sub rsp, 0x38
    """

    # Signature de la fonction SidecarDisplayIsSupportedReceivingDevice
    # push rbp; mov rbp, rsp; push r15; push r14; push r13; push r12; push rbx; sub rsp, 0x38
    function_signature = b'\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x83\xec\x38'

    print(f"🔍 Recherche de la signature: {' '.join(f'{b:02X}' for b in function_signature)}")

    # Chercher dans le binaire
    offset = binary_data.find(function_signature)

    if offset != -1:
        print(f"✅ Fonction trouvée à l'offset: 0x{offset:x}")

        # Afficher quelques bytes pour vérification
        context = binary_data[offset:offset + 32]
        print(f"🔍 Contexte: {' '.join(f'{b:02X}' for b in context)}")
        return offset
    else:
        print("❌ Signature exacte non trouvée")
        return None


def find_alternative_patterns(binary_data):
    """Cherche des patterns alternatifs si la signature exacte n'est pas trouvée"""

    patterns = [
        # Pattern 1: Début classique avec push rbp; mov rbp, rsp
        (b'\x55\x48\x89\xe5', "push rbp; mov rbp, rsp"),

        # Pattern 2: Séquence spécifique vue dans le PDF
        (b'\x48\x89\xe5\x41\x57\x41\x56', "mov rbp, rsp; push r15; push r14"),

        # Pattern 3: Call vers objc_getAssociatedObject (vu dans le code)
        (b'\xe8.*\x48\x85\xc0\x74', "call ...; test rax, rax; je"),
    ]

    print("\n🔍 Recherche de patterns alternatifs...")

    for pattern, description in patterns:
        print(f"   Cherche: {description}")

        import re
        if b'.*' in pattern:
            # Pattern regex pour les calls avec offsets variables
            matches = list(re.finditer(pattern, binary_data))
            if matches:
                for match in matches[:3]:  # Max 3 résultats
                    offset = match.start()
                    print(f"   ✅ Trouvé à 0x{offset:x}")

                    # Vérifier si c'est dans une zone de code probable
                    context = binary_data[max(0, offset - 16):offset + 32]
                    print(f"   🔍 Contexte: {' '.join(f'{b:02X}' for b in context)}")

                    return offset
        else:
            offset = binary_data.find(pattern)
            if offset != -1:
                print(f"   ✅ Trouvé à 0x{offset:x}")

                # Chercher le début de la fonction (push rbp précédent)
                function_start = binary_data.rfind(b'\x55', max(0, offset - 50), offset)
                if function_start != -1 and binary_data[function_start:function_start + 4] == b'\x55\x48\x89\xe5':
                    print(f"   🎯 Début de fonction probable à 0x{function_start:x}")
                    return function_start

                return offset

    return None


def verify_patch_location(binary_data, offset):
    """Vérifie que l'offset est bien au début d'une fonction"""

    if offset < 0 or offset >= len(binary_data) - 20:
        return False

    # Vérifier que ça commence par push rbp (0x55)
    if binary_data[offset] != 0x55:
        print(f"⚠️  L'offset 0x{offset:x} ne commence pas par 'push rbp' (0x55)")

        # Chercher le push rbp le plus proche
        for i in range(max(0, offset - 10), min(len(binary_data) - 4, offset + 10)):
            if binary_data[i:i + 4] == b'\x55\x48\x89\xe5':
                print(f"🔍 'push rbp; mov rbp, rsp' trouvé à 0x{i:x}")
                return i
        return False

    print(f"✅ Offset 0x{offset:x} validé")
    return offset


def apply_precise_patch(binary_path, output_path=None):
    """Applique le patch de manière précise"""

    if output_path is None:
        output_path = binary_path.replace(".exe", "_patched.exe") if binary_path.endswith(
            ".exe") else binary_path + "_patched"

    print("🚀 Application du patch précis...")

    try:
        # Lire le binaire
        with open(binary_path, 'rb') as f:
            binary_data = bytearray(f.read())

        print(f"📁 Binaire chargé: {len(binary_data)} bytes")

        # Chercher la fonction
        offset = find_function_signature(binary_data)

        if offset is None:
            print("⚠️  Signature exacte non trouvée, recherche de patterns alternatifs...")
            offset = find_alternative_patterns(binary_data)

        if offset is None:
            print("❌ Impossible de localiser la fonction")
            return False

        # Vérifier et ajuster l'offset si nécessaire
        validated_offset = verify_patch_location(binary_data, offset)
        if validated_offset is False:
            print("❌ Impossible de valider l'emplacement du patch")
            return False

        if validated_offset != offset:
            offset = validated_offset
            print(f"🔧 Offset ajusté à: 0x{offset:x}")

        # Sauvegarder les bytes originaux
        original_bytes = binary_data[offset:offset + 20]
        print(f"💾 Bytes originaux: {' '.join(f'{b:02X}' for b in original_bytes)}")

        # Patch: MOV EAX, 1; RET (toujours retourner TRUE)
        patch_bytes = b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret

        # Appliquer le patch
        binary_data[offset:offset + len(patch_bytes)] = patch_bytes

        # Optionnel: NOPer quelques bytes suivants pour éviter des problèmes
        nop_count = min(10, len(original_bytes) - len(patch_bytes))
        binary_data[offset + len(patch_bytes):offset + len(patch_bytes) + nop_count] = b'\x90' * nop_count

        # Sauvegarder le binaire patché
        with open(output_path, 'wb') as f:
            f.write(binary_data)

        print(f"✅ Patch appliqué à l'offset 0x{offset:x}")
        print(f"🔧 Bytes du patch: {' '.join(f'{b:02X}' for b in patch_bytes)}")
        print(f"💾 Fichier patché: {output_path}")

        # Vérification
        with open(output_path, 'rb') as f:
            patched_data = f.read()
            patched_bytes = patched_data[offset:offset + len(patch_bytes)]
            if patched_bytes == patch_bytes:
                print("✅ Patch vérifié avec succès!")
                return True
            else:
                print("❌ Erreur de vérification du patch")
                return False

    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False


def show_manual_instructions():
    """Affiche les instructions pour patch manuel avec les informations exactes du PDF"""

    print("\n🛠️  Instructions pour patch manuel (éditeur hexadécimal):")
    print("=" * 60)
    print("D'après l'analyse du PDF, la fonction commence par:")
    print("   Signature: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 38")
    print("   (push rbp; mov rbp,rsp; push r15; push r14; push r13; push r12; push rbx; sub rsp,0x38)")
    print()
    print("1. Ouvrez SidecarCore.exe dans un éditeur hexadécimal")
    print("2. Recherchez (Ctrl+F) la séquence: 55 48 89 E5 41 57 41 56")
    print("3. Remplacez les premiers bytes par: B8 01 00 00 00 C3")
    print("   (ceci fait: MOV EAX, 1; RET - retourne toujours TRUE)")
    print("4. Optionnel: ajoutez des NOP (90) après pour combler")
    print("5. Sauvegardez le fichier")
    print()
    print("🎯 Résultat attendu:")
    print("   Avant: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 38...")
    print("   Après: B8 01 00 00 00 C3 90 90 90 90 90 90 90 90 90 90...")


def main():
    """Fonction principale"""

    print("🎯 SidecarCore Patcher - Version Précise")
    print("Basé sur l'analyse du code assembleur du PDF")
    print("=" * 55)

    # Obtenir le chemin du fichier
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
    else:
        binary_path = "./SidecarCore.exe"
        if not os.path.exists(binary_path):
            binary_path = input("📂 Chemin vers SidecarCore.exe: ").strip()

    if not os.path.exists(binary_path):
        print(f"❌ Fichier non trouvé: {binary_path}")
        sys.exit(1)

    # Créer un backup
    backup_path = binary_path + ".backup"
    if not os.path.exists(backup_path):
        print(f"💾 Création du backup: {backup_path}")
        shutil.copy2(binary_path, backup_path)
    else:
        print(f"ℹ️  Backup existe déjà: {backup_path}")

    # Appliquer le patch
    success = apply_precise_patch(binary_path)

    if success:
        print("\n🎉 SUCCÈS! Le patch a été appliqué avec succès!")
        print("🔓 Tous les appareils devraient maintenant être autorisés pour Sidecar")
        print()
        print("📋 Prochaines étapes:")
        print("   1. Testez avec différents appareils")
        print("   2. Si problème, restaurez avec: cp backup original")
    else:
        print("\n⚠️  Patch automatique échoué")
        show_manual_instructions()

        # Option pour essai avec offset manuel du PDF
        print(f"\n💡 D'après votre PDF, essayons l'adresse exacte...")
        manual_offset = input("Offset manuel en hex (laissez vide pour ignorer): ").strip()
        if manual_offset:
            try:
                offset = int(manual_offset, 16)
                print(f"🎯 Tentative avec offset 0x{offset:x}")

                with open(binary_path, 'rb') as f:
                    data = bytearray(f.read())

                patch = b'\xB8\x01\x00\x00\x00\xC3'
                data[offset:offset + len(patch)] = patch

                output = binary_path.replace('.exe', '_manual_patched.exe')
                with open(output, 'wb') as f:
                    f.write(data)

                print(f"✅ Patch manuel appliqué: {output}")

            except ValueError:
                print("❌ Offset hexadécimal invalide")


if __name__ == "__main__":
    main()
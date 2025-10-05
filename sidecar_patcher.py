#!/usr/bin/env python3
"""Patch binaire minimaliste pour SidecarCore."""
from __future__ import annotations

import argparse
import pathlib
from dataclasses import dataclass
from typing import Optional, Sequence

SIGNATURE = bytes(
    [
        0x55,
        0x48,
        0x89,
        0xE5,
        0x41,
        0x57,
        0x41,
        0x56,
        0x41,
        0x55,
        0x41,
        0x54,
        0x53,
        0x48,
        0x83,
        0xEC,
        0x38,
    ]
)
PATCH_BYTES = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
DEFAULT_NOP_COUNT = 10


@dataclass(frozen=True)
class PatchInfo:
    """Informations sur l'opération de patch."""

    offset: int
    original_bytes: bytes


class PatchError(RuntimeError):
    """Erreur levée lors d'un patch impossible."""


def load_binary(path: pathlib.Path) -> bytearray:
    """Lit un fichier binaire et renvoie son contenu sous forme de bytearray."""

    if not path.exists():
        raise PatchError(f"Fichier introuvable: {path}")

    return bytearray(path.read_bytes())


def save_binary(path: pathlib.Path, data: bytearray) -> None:
    """Écrit les données patchées sur disque."""

    path.write_bytes(data)


def find_patch_offset(
    data: Sequence[int], signature: bytes = SIGNATURE
) -> Optional[int]:
    """Recherche la signature binaire attendue et renvoie son offset."""

    buffer: Sequence[int]
    if isinstance(data, (bytes, bytearray, memoryview)):
        buffer = data
    else:
        buffer = bytes(data)

    offset = buffer.find(signature)  # type: ignore[arg-type]
    return offset if offset != -1 else None


def apply_patch(
    data: bytearray,
    offset: int,
    patch: bytes = PATCH_BYTES,
    nop_count: int = DEFAULT_NOP_COUNT,
) -> PatchInfo:
    """Applique le patch au buffer fourni."""

    if offset < 0:
        raise PatchError("Offset négatif invalide")

    if offset + len(patch) > len(data):
        raise PatchError("Offset en dehors des limites du fichier")

    end_of_patch = offset + len(patch) + max(0, nop_count)
    if end_of_patch > len(data):
        raise PatchError("Le patch dépasse la taille du fichier")

    original_slice = bytes(data[offset:end_of_patch])
    data[offset : offset + len(patch)] = patch

    if nop_count > 0:
        data[offset + len(patch) : end_of_patch] = b"\x90" * nop_count

    return PatchInfo(offset=offset, original_bytes=original_slice)


def create_backup(path: pathlib.Path) -> pathlib.Path:
    """Crée une sauvegarde du fichier original."""

    backup_path = path.with_suffix(path.suffix + ".bak")
    if backup_path.exists():
        return backup_path

    backup_path.write_bytes(path.read_bytes())
    return backup_path


def parse_offset(value: str) -> int:
    """Analyse un offset fourni par l'utilisateur (décimal ou hexadécimal)."""

    base = 16 if value.lower().startswith("0x") else 10
    try:
        return int(value, base=base)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Offset invalide: {value}") from exc


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Construit et analyse les arguments de la ligne de commande."""

    parser = argparse.ArgumentParser(
        description="Applique un patch sur la fonction SidecarDisplayIsSupportedReceivingDevice",
    )
    parser.add_argument("binary", type=pathlib.Path, help="Chemin vers le binaire SidecarCore à patcher")
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        help="Chemin du fichier patché (par défaut: <fichier>.patched)",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Ne crée pas de sauvegarde lorsque l'on patche le fichier original",
    )
    parser.add_argument(
        "--force-offset",
        type=parse_offset,
        help="Offset personnalisé (décimal ou hexadécimal 0x...)",
    )
    parser.add_argument(
        "--nop-count",
        type=int,
        default=DEFAULT_NOP_COUNT,
        help=f"Nombre de NOP à insérer après le patch (défaut: {DEFAULT_NOP_COUNT})",
    )
    return parser.parse_args(argv)


def resolve_output_path(input_path: pathlib.Path, output_argument: Optional[pathlib.Path]) -> pathlib.Path:
    """Détermine le chemin de sortie du binaire patché."""

    if output_argument is not None:
        return output_argument

    return input_path.with_name(input_path.name + ".patched")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Point d'entrée principal du script."""

    args = parse_arguments(argv)
    binary_path = args.binary

    try:
        data = load_binary(binary_path)
    except PatchError as exc:
        print(exc)
        return 1

    offset: Optional[int]
    if args.force_offset is not None:
        offset = args.force_offset
    else:
        offset = find_patch_offset(data)
        if offset is None:
            print("Signature introuvable dans le fichier fourni.")
            return 1

    try:
        info = apply_patch(data, offset, nop_count=max(0, args.nop_count))
    except PatchError as exc:
        print(exc)
        return 1

    output_path = resolve_output_path(binary_path, args.output)

    if output_path == binary_path:
        if not args.no_backup:
            backup = create_backup(binary_path)
            print(f"Sauvegarde créée: {backup}")
        save_binary(binary_path, data)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        save_binary(output_path, data)

    print(f"Patch appliqué à l'offset 0x{info.offset:X}.")
    print(
        "Octets originaux: ",
        " ".join(f"{byte:02X}" for byte in info.original_bytes),
    )
    if output_path == binary_path:
        print(f"Fichier patché mis à jour: {binary_path}")
    else:
        print(f"Fichier patché écrit: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

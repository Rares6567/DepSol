#!/usr/bin/env python3
"""Conservatively complete a LineageOS blob list from an extracted dump."""

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
import difflib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tempfile

PLATFORM = frozenset({"libc.so", "libm.so", "libdl.so", "liblog.so"})
PARTITIONS = {"vendor", "odm", "system", "system_ext", "product"}


def safe_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe blob path: {value!r}")
    return str(path)


def partition(path):
    first = PurePosixPath(path).parts[0]
    return first if first in PARTITIONS else "system"


@dataclass(frozen=True)
class Entry:
    source: str
    destination: str
    disabled: bool = False
    aliases: tuple = ()


def parse_list(text):
    entries = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Hashes and extraction arguments belong to the original line; never rewrite it.
        spec = line.split("|", 1)[0]
        path, *options = spec.lstrip("-").split(";")
        paths = path.split(":")
        if len(paths) > 2:
            raise ValueError(f"line {number}: invalid source:destination")
        source = safe_path(paths[0])
        destination = safe_path(paths[-1])
        aliases = tuple(safe_path(alias) for option in options
                        if option.startswith("SYMLINK=")
                        for alias in option.split("=", 1)[1].split(","))
        entries.append(Entry(source, destination, "DISABLE_CHECKELF" in options, aliases))
    return entries


def elf_abi(path):
    """ELF class, byte order, and e_machine, or None for non-ELF files."""
    with path.open("rb") as stream:
        header = stream.read(20)
    if not header.startswith(b"\x7fELF"):
        return None
    if len(header) < 20 or header[4] not in (1, 2) or header[5] not in (1, 2):
        raise ValueError(f"invalid ELF header: {path}")
    machine = struct.unpack("<H" if header[5] == 1 else ">H", header[18:20])[0]
    return header[4], header[5], machine


class Dump:
    def __init__(self, root, readelf):
        self.root = root.resolve()
        self.readelf = readelf
        self.abi_cache = {}
        self.needed_cache = {}
        self.index = defaultdict(list)
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            dirs.sort()
            for name in sorted(files):
                if ".so" in name:
                    path = Path(directory) / name
                    relative = path.relative_to(self.root).as_posix()
                    if self.contained(path):
                        self.index[name].append(relative)

    def contained(self, path):
        return path.resolve().is_relative_to(self.root)

    def locate(self, relative):
        variants = [relative]
        if relative.startswith(("vendor/", "odm/", "product/", "system_ext/")):
            variants.append("system/" + relative)
        elif not relative.startswith("system/"):
            variants.append("system/" + relative)
        for variant in variants:
            path = self.root / variant
            if path.is_file() and self.contained(path):
                return path
        return None

    def abi(self, path):
        if path not in self.abi_cache:
            self.abi_cache[path] = elf_abi(path)
        return self.abi_cache[path]

    def needed(self, path):
        if path not in self.needed_cache:
            result = subprocess.run([self.readelf, "--dynamic", "--wide", str(path)],
                                    text=True, capture_output=True,
                                    env={**os.environ, "LC_ALL": "C"})
            if result.returncode:
                raise ValueError(f"readelf failed for {path}: {result.stderr.strip()}")
            self.needed_cache[path] = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", result.stdout)
        return self.needed_cache[path]

    @staticmethod
    def canonical(relative):
        if relative.startswith("system/") and relative.split("/")[1] in PARTITIONS - {"system"}:
            return relative.removeprefix("system/")
        return relative


class Resolver:
    def __init__(self, dump, entries, platform):
        self.dump = dump
        self.entries = entries
        self.platform = platform
        self.providers = defaultdict(list)
        self.additions = []
        self.unresolved = []
        self.errors = []
        self.queue = deque()
        self.visited = set()

    def register(self, entry, path, abi):
        for destination in (entry.destination, *entry.aliases):
            self.providers[PurePosixPath(destination).name].append((destination, abi))
        if path is not None and abi is not None and not entry.disabled:
            self.queue.append((entry.destination, path, abi))

    def run(self):
        for entry in self.entries:
            path = self.dump.locate(entry.destination) or self.dump.locate(entry.source)
            if path is None:
                self.errors.append(f"listed blob missing: {entry.source}")
                continue
            try:
                self.register(entry, path, self.dump.abi(path))
            except (OSError, ValueError) as error:
                self.errors.append(str(error))
        while self.queue:
            destination, path, abi = self.queue.popleft()
            identity = (destination, path)
            if identity in self.visited:
                continue
            self.visited.add(identity)
            try:
                needed = self.dump.needed(path)
            except (OSError, ValueError) as error:
                self.errors.append(str(error))
                continue
            for name in needed:
                self.resolve(destination, abi, name)
        return self.additions

    def resolve(self, consumer, abi, name):
        scope = partition(consumer)
        listed = [destination for destination, provider_abi in self.providers[name]
                  if provider_abi == abi and partition(destination) == scope]
        if listed:
            return
        if name in self.platform:
            return
        candidates = []
        for relative in self.dump.index.get(name, []):
            destination = self.dump.canonical(relative)
            if partition(destination) != scope:
                continue
            parts = PurePosixPath(destination).parts
            library_root = 1 if parts[0] in PARTITIONS else 0
            if len(parts) != library_root + 2 or parts[library_root] not in ("lib", "lib64"):
                continue
            path = self.dump.root / relative
            try:
                if self.dump.abi(path) == abi:
                    candidates.append((destination, path))
            except (OSError, ValueError) as error:
                self.errors.append(str(error))
        if len(candidates) != 1:
            reason = ("ambiguous: " + ", ".join(str(path.relative_to(self.dump.root))
                                             for _, path in candidates)
                      if candidates else "no compatible library in the partition search root")
            other = self.dump.index.get(name, [])
            if not candidates and other:
                reason += "; dump candidates: " + ", ".join(other)
            self.unresolved.append((consumer, name, reason))
            print(f"  {name}: UNRESOLVED (needed by {consumer}; {reason})")
            return
        destination, path = candidates[0]
        if any(destination in (entry.destination, *entry.aliases) for entry in self.entries):
            reason = "already listed but its source/ABI could not be verified"
            self.unresolved.append((consumer, name, reason))
            print(f"  {name}: UNRESOLVED (needed by {consumer}; {reason})")
            return
        print(f"  {name}: RESOLVED_PROPRIETARY (+ {destination})")
        self.additions.append(destination)
        entry = Entry(destination, destination)
        self.entries.append(entry)
        self.register(entry, path, abi)


def updated_text(original, additions):
    if not additions:
        return original
    newline = "\r\n" if "\r\n" in original else "\n"
    separator = "" if not original or original.endswith(("\r", "\n")) else newline
    return (original + separator + newline + "# Automatically resolved ELF dependencies" + newline
            + newline.join(additions) + newline)


def atomic_write(path, text, expected):
    if path.is_symlink():
        raise ValueError("refusing to replace a symlinked blob list; use its real path")
    if path.read_bytes() != expected:
        raise ValueError("blob list changed during scanning; run again")
    mode = path.stat().st_mode & 0o777
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("blob_list", type=Path)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="show a diff without writing")
    parser.add_argument("--readelf", help="llvm-readelf or GNU readelf executable")
    parser.add_argument("--platform-libs", type=Path,
                        help="additional build-provided library names, one per line (# comments allowed)")
    args = parser.parse_args(argv)
    try:
        if not args.dump.is_dir():
            raise ValueError(f"dump is not a directory: {args.dump}")
        readelf = args.readelf or shutil.which("llvm-readelf") or shutil.which("readelf")
        if not readelf or not shutil.which(readelf):
            raise ValueError("install llvm-readelf or GNU readelf, or set --readelf")
        original_bytes = args.blob_list.read_bytes()
        original = original_bytes.decode("utf-8")
        platform = set(PLATFORM)
        if args.platform_libs:
            for line in args.platform_libs.read_text().splitlines():
                name = line.split("#", 1)[0].strip()
                if name:
                    if "/" in name or any(char.isspace() for char in name):
                        raise ValueError(f"invalid platform library name: {name!r}")
                    platform.add(name)
        resolver = Resolver(Dump(args.dump, readelf), parse_list(original), platform)
        additions = resolver.run()
        updated = updated_text(original, additions)
        if args.dry_run:
            sys.stdout.writelines(difflib.unified_diff(original.splitlines(keepends=True),
                                  updated.splitlines(keepends=True),
                                  fromfile=str(args.blob_list), tofile=str(args.blob_list) + " (resolved)"))
        elif additions:
            atomic_write(args.blob_list, updated, original_bytes)
        for error in resolver.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"{'Would add' if args.dry_run else 'Added'} {len(additions)} blob(s). "
              f"{len(resolver.unresolved)} unresolved dependencies. {len(resolver.errors)} scan errors.")
        return 1 if resolver.unresolved or resolver.errors else 0
    except (OSError, ValueError, UnicodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

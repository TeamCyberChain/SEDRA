#!/usr/bin/env python3
"""Reproduce official CERT r4.2 acquisition and optional selective extraction.

No credentials are required. The 4.8 GB archive is not included in the source zip.
Downloads preserve normal system proxy/TLS configuration. Only known regular tar
members are copied; no archive path is trusted as an output path.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import shutil
import tarfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

FILES = {
    "distribution.json": ("https://api.figshare.com/v2/articles/12841247", None, None),
    "README.txt": ("https://ndownloader.figshare.com/files/24860765", 1446, None),
    "SHA256.txt": ("https://ndownloader.figshare.com/files/24857831", 868, None),
    "answers.tar.bz2": ("https://ndownloader.figshare.com/files/24857828", 1254678, "ed21bf921def01e97326b314f2d1fa77651a945bd31bf513095f8ac7658c9ddd"),
    "r4.2.tar.bz2": ("https://ndownloader.figshare.com/files/24856766", 4824287500, "586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c"),
}


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(path, url, size, expected):
    if path.exists():
        observed = checksum(path)
        if (size is None or path.stat().st_size == size) and (expected is None or observed == expected):
            print(f"Verified existing {path.name}: {path.stat().st_size:,} bytes", flush=True)
            return observed
        raise ValueError(f"Existing {path} does not match expected metadata; preserve it and inspect before retrying")
    partial = path.with_suffix(path.suffix + ".part")
    offset = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(url, headers={"User-Agent": "SADD-hackathon-data-intake/1.0", **({"Range": f"bytes={offset}-"} if offset else {})})
    with urllib.request.urlopen(request, timeout=60) as response:
        if offset and response.status == 206:
            content_range = response.headers.get("Content-Range", "")
            if not content_range.startswith(f"bytes {offset}-"):
                raise ValueError("Range response did not begin at the requested offset")
            mode = "ab"
        else:
            offset, mode = 0, "wb"
        last_report = offset
        with partial.open(mode) as target:
            while True:
                block = response.read(4 * 1024 * 1024)
                if not block:
                    break
                target.write(block)
                offset += len(block)
                if offset - last_report >= 128 * 1024 * 1024:
                    print(f"{path.name}: {offset:,} bytes downloaded", flush=True)
                    last_report = offset
    if size is not None and partial.stat().st_size != size:
        raise ValueError(f"Incomplete {path.name}: expected {size}, got {partial.stat().st_size}")
    observed = checksum(partial)
    if expected and observed != expected:
        raise ValueError(f"Checksum mismatch for {path.name}; partial file preserved")
    partial.replace(path)
    print(f"Verified {path.name}: {path.stat().st_size:,} bytes", flush=True)
    return observed


def extract_selected(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    extracted = []
    print("Streaming archive; selecting release README, file.csv and LDAP CSVs only", flush=True)
    # BZ2File handles concatenated bzip2 streams found in this distribution;
    # tarfile's streaming r|bz2 decompressor only handles one compressed stream.
    with bz2.open(archive, "rb") as compressed, tarfile.open(fileobj=compressed, mode="r|") as bundle:
        for member in bundle:
            if not member.isfile():
                continue
            name = PurePosixPath(member.name)
            lower_parts = [p.lower() for p in name.parts]
            if name.name.lower() == "file.csv":
                relative = Path("file.csv")
            elif name.name.lower().startswith("readme"):
                relative = Path("release-README.txt")
            elif "ldap" in lower_parts and name.suffix.lower() == ".csv":
                relative = Path("LDAP") / name.name
            else:
                continue
            if member.size > 20 * 1024**3:
                raise ValueError("Selected member exceeds the declared extraction size bound")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise ValueError(f"Refusing to overwrite an extracted member: {target}")
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("Selected member has no readable bytes")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, 4 * 1024 * 1024)
            if target.stat().st_size != member.size:
                raise ValueError(f"Extracted member length mismatch: {relative}")
            extracted.append({"archive_member": member.name, "local_path": str(relative), "bytes": member.size, "sha256": checksum(target)})
            print(f"Extracted {relative}: {member.size:,} bytes", flush=True)
    if not any(row["local_path"] == "file.csv" for row in extracted):
        raise ValueError("Archive contains no expected file.csv")
    (destination / "extraction_manifest.json").write_text(json.dumps({"archive": archive.name, "members": extracted}, indent=2), encoding="utf-8")
    return extracted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path("data/cert"))
    parser.add_argument("--extract", action="store_true", help="Extract only file.csv, release README and LDAP")
    parser.add_argument("--extract-only", action="store_true", help="Use an already downloaded, checksum-verified archive")
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    rows = []
    if not args.extract_only:
        for name, (url, size, expected) in FILES.items():
            observed = fetch(args.destination / name, url, size, expected)
            rows.append({"name": name, "source_url": url, "bytes": (args.destination / name).stat().st_size, "sha256": observed, "official_sha256_verified": expected is not None})
        (args.destination / "acquisition_manifest.json").write_text(json.dumps({"dataset": "CERT r4.2", "provenance": "public_synthetic_benchmark", "acquired_unix": time.time(), "files": rows}, indent=2), encoding="utf-8")
    if args.extract or args.extract_only:
        archive = args.destination / "r4.2.tar.bz2"
        expected = FILES[archive.name][2]
        observed = checksum(archive)
        if observed != expected:
            raise ValueError("Official archive SHA-256 does not match; extraction stopped")
        print(f"Official r4.2 SHA-256 verified: {observed}", flush=True)
        extract_selected(archive, args.destination / "extracted")


if __name__ == "__main__":
    main()

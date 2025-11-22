#!/usr/bin/env python3

"""
MIT License

Copyright (c) 2025 Michael Borgmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict
from Crypto.Cipher import AES

# ───────────────────────────────────────────────
# AES-GCM decrypt
# ───────────────────────────────────────────────
def decrypt_aes_gcm(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("Invalid AES-GCM blob")

    nonce = blob[:12]
    tag = blob[-16:]
    ciphertext = blob[12:-16]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ───────────────────────────────────────────────
# Decrypt manifest
# ───────────────────────────────────────────────
def decrypt_manifest(manifest_path: Path, key: bytes) -> Dict[str, Any]:
    encrypted = manifest_path.read_bytes()
    plaintext = decrypt_aes_gcm(key, encrypted)
    return json.loads(plaintext.decode("utf-8"))

# ───────────────────────────────────────────────
# Decrypt a single file
# ───────────────────────────────────────────────
def decrypt_file(src: Path, dst: Path, key: bytes):
    data = decrypt_aes_gcm(key, src.read_bytes())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)

# ───────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Decrypt encrypted repo with restored folder structure")
    parser.add_argument("--input", required=True, help="Folder containing manifest.bin and UUID files")
    parser.add_argument("--output", required=True, help="Where decrypted files should be placed")
    parser.add_argument("--key", required=True, help="AES key in 64-char hex")
    parser.add_argument("--write-manifest", action="store_true", help="Write plaintext manifest.json")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    key = bytes.fromhex(args.key)
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")

    # Decrypt manifest
    manifest = decrypt_manifest(input_dir / "manifest.bin", key)

    if args.write_manifest:
        out_manifest = output_dir / "manifest.json"
        out_manifest.parent.mkdir(parents=True, exist_ok=True)
        out_manifest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
        print(f"✔ manifest.json restored → {out_manifest}")

    # Decrypt all resources
    for uuid_name, info in manifest.get("files", {}).items():
        original_path = Path(info["originalPath"])
        src_file = input_dir / f"{uuid_name}.bin"
        dst_file = output_dir / original_path

        if not src_file.exists():
            print(f"⚠ Missing encrypted file: {uuid_name}.bin")
            continue

        decrypt_file(src_file, dst_file, key)
        print(f"✔ {uuid_name}.bin → {dst_file.relative_to(output_dir)}")

    print("\n🎉 All resources successfully decrypted with folder structure restored.")

if __name__ == "__main__":
    main()

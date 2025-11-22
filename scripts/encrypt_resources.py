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
import base64
import json
import uuid
from pathlib import Path
from typing import Dict, Any, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import mimetypes
import datetime

# ───────────────────────────────────────────────────────────────
# AES-GCM ENCRYPTION
# ───────────────────────────────────────────────────────────────
def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

# ───────────────────────────────────────────────────────────────
# ENCRYPT FILE & RETURN MANIFEST ENTRY
# ───────────────────────────────────────────────────────────────
def encrypt_file(key: bytes, src_path: Path, dst_path: Path, input_dir: Path) -> Dict[str, Any]:
    data = src_path.read_bytes()
    nonce, ciphertext, tag = encrypt_aes_gcm(key, data)
    encrypted_blob = nonce + ciphertext + tag
    dst_path.write_bytes(encrypted_blob)

    # Determine type from extension or mime
    ext = src_path.suffix.lower()
    type_guess = mimetypes.guess_type(src_path.name)[0]
    file_type = type_guess.split("/")[0] if type_guess else ext[1:] if ext else "bin"

    return {
        "size": len(encrypted_blob),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "sha256": None,  # optional
        "originalPath": str(src_path.relative_to(input_dir)),
        "type": file_type
    }

# ───────────────────────────────────────────────────────────────
# BUILD ENCRYPTED RESOURCE REPO
# ───────────────────────────────────────────────────────────────
def build_repository(input_dir: Path, output_dir: Path, key: bytes) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "formatVersion": 1,
        "generatedAt": None,
        "files": {}
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    for path in input_dir.rglob("*"):
        if path.is_dir():
            continue

        file_uuid = str(uuid.uuid4())
        dst_path = output_dir / f"{file_uuid}.bin"

        entry = encrypt_file(key, path, dst_path, input_dir)
        manifest["files"][file_uuid] = entry

    manifest["generatedAt"] = datetime.datetime.utcnow().isoformat() + "Z"
    return manifest

# ───────────────────────────────────────────────────────────────
# ENCRYPT MANIFEST INTO manifest.bin
# ───────────────────────────────────────────────────────────────
def encrypt_manifest(key: bytes, manifest: Dict[str, Any], output_dir: Path):
    plaintext = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
    nonce, ciphertext, tag = encrypt_aes_gcm(key, plaintext)
    blob = nonce + ciphertext + tag
    (output_dir / "manifest.bin").write_bytes(blob)

# ───────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Encrypt all resources for public GitHub hosting.")
    parser.add_argument("--input", required=True, help="Path to original unencrypted resource folder")
    parser.add_argument("--output", required=True, help="Folder to write encrypted GitHub-ready files")
    parser.add_argument("--key", required=True, help="AES-256 key in hex format (64 hex chars)")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    aes_key = bytes.fromhex(args.key)
    if len(aes_key) != 32:
        raise ValueError("AES key must be exactly 32 bytes (64 hex chars).")

    manifest = build_repository(input_dir, output_dir, aes_key)
    encrypt_manifest(aes_key, manifest, output_dir)

    print(f"✔ Done! Encrypted repository built at: {output_dir}")
    print(f"✔ Encrypted files: {len(manifest['files'])}")
    print("✔ Upload this folder to GitHub as your public runtime-data-support repo.")

if __name__ == "__main__":
    main()

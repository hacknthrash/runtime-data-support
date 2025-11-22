# `runtime-data-support`

This repository contains **encrypted resources** for app development. All resources are **all rights reserved** and intended for internal development use. The encryption ensures the resources can be hosted **publicly** without revealing their content.

The repository also includes **open-source scripts** to encrypt and decrypt resources for local use.

---

## Repository Contents

```
data/                     # Encrypted resources (proprietary)
    manifest.bin          # Encrypted manifest of all resources
    <UUID>.bin            # Encrypted individual files
scripts/                  # Open-source scripts
    encrypt_resources.py
    decrypt_resources.py
README.md
```

* `data/` contains the encrypted resource files and is **all rights reserved**.
* `scripts/` contains tools to encrypt/decrypt resources. These are MIT-licensed.

---

## Scripts

### Encrypt Resources

```bash
python3 scripts/encrypt_resources.py \
    --input path/to/original/resources \
    --output path/to/encrypted/data \
    --key <32-byte-hex-key>
```

* `--input`: Path to your original resource folder.
* `--output`: Folder where encrypted files will be written.
* `--key`: AES-256 key in **hexadecimal (64 characters)** format.

The script generates:

* Encrypted files (`<UUID>.bin`) for each resource.
* `manifest.bin` containing metadata about all resources.

---

### Decrypt Resources

```bash
python3 scripts/decrypt_resources.py \
    --input path/to/encrypted/data \
    --output path/to/decrypted/resources \
    --key <32-byte-hex-key>
```

* Decrypts `manifest.bin` and all resources.
* Restores the original folder structure and filenames.
* Optionally, you can write a plaintext `manifest.json` with `--write-manifest`.

---

## Workflow

1. Prepare original assets in your folder, e.g., `original/gita/`.
2. Encrypt with:

```bash
python3 scripts/encrypt_resources.py \
    --input original/gita \
    --output data \
    --key <32-byte-hex-key>
```

3. The `data/` folder can be **publicly committed** to GitHub safely.
4. For local development or testing in the app:

```bash
python3 scripts/decrypt_resources.py \
    --input data \
    --output decrypt \
    --key <32-byte-hex-key>
```

5. Your original folder structure is restored in `decrypt/`.

---

## Dependencies

It is recommended to use a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome
```

* `pycryptodome` is required for AES-GCM encryption/decryption.

---

## Security

* All assets are encrypted using **AES-256 GCM** with random nonces.
* Each file has a unique UUID filename; the folder structure is stored in the manifest.
* The repository can be public without exposing your app resources.
* The encryption scripts are open-source (MIT license); the assets remain proprietary.
* **Note:** Losing the AES key means the encrypted resources cannot be recovered.

---

## License

* **Scripts (`encrypt_resources.py`, `decrypt_resources.py`)**: MIT License — free to use and modify.
* **Data**: All rights reserved — do **not** redistribute outside your app.
# ProtonMail-PGP-Key-Parser
ProtonMail PGP Key Parser
# ProtonMail PGP Key Parser 🔐

This Python script fetches and parses public PGP keys from [ProtonMail's public key server](https://mail-api.proton.me/pks/lookup). It extracts structured metadata such as key fingerprints, capabilities, expiration, and user ID preferences.

---

## Features

- Fetches public keys directly via ProtonMail's keyserver API
- Parses:
  - Primary key metadata
  - User ID capabilities & preferences
  - Subkey info including key flags
- Handles missing attributes and edge cases safely
- CLI-based and easy to extend

---

## Requirements

- Python 3.7+
- [PGPy](https://github.com/SecurityInnovation/PGPy)

Install with:

```bash
pip install pgpy requests

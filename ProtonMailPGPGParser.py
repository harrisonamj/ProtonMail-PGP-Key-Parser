import requests
from pgpy import PGPKey, PGPUID
from pgpy.errors import PGPError
from typing import Dict, Any
from pprint import pprint


def get_and_parse_protonmail_key(email: str) -> Dict[str, Any]:
    url = f"https://mail-api.proton.me/pks/lookup?op=get&search={email}"
    response = requests.get(url)

    if response.status_code != 200 or "BEGIN PGP PUBLIC KEY BLOCK" not in response.text:
        return {"error": "Failed to retrieve a valid PGP public key from ProtonMail."}

    try:
        key, _ = PGPKey.from_blob(response.text)
    except PGPError as e:
        return {"error": f"Error parsing PGP key: {e}"}

    # Safe revocation check for primary key
    is_revoked = any(getattr(sig, "is_revocation", False) for sig in getattr(key, "_signatures", []))

    key_info = {
        "Primary Key": {
            "Fingerprint": key.fingerprint,
            "Key ID": key.fingerprint[-16:],
            "Key Algorithm": str(key.key_algorithm),
            "Created": str(key.created),
            "Expires": str(key.expires_at) if key.expires_at else "Never",
            "Key Size": key.key_size,
            "Is Revoked": is_revoked,
            "User IDs": [],
            "Capabilities": "Unknown",
            "Preferences": {}
        },
        "Subkeys": []
    }

    # Parse capabilities and preferences from first available UID self-signature
    for uid_obj in key.userids:
        uid: PGPUID = uid_obj
        key_info["Primary Key"]["User IDs"].append(str(uid))

        sig = getattr(uid, "selfsig", None)
        if sig:
            # Capabilities
            if hasattr(sig, "key_flags") and sig.key_flags:
                key_info["Primary Key"]["Capabilities"] = ", ".join(flag.name for flag in sig.key_flags)

            # Preferences
            prefs = {}
            if hasattr(sig, "preferred_symmetric_algorithms") and sig.preferred_symmetric_algorithms:
                prefs["Symmetric"] = [algo.name for algo in sig.preferred_symmetric_algorithms]
            if hasattr(sig, "preferred_hash_algorithms") and sig.preferred_hash_algorithms:
                prefs["Hash"] = [algo.name for algo in sig.preferred_hash_algorithms]
            if hasattr(sig, "preferred_compression_algorithms") and sig.preferred_compression_algorithms:
                prefs["Compression"] = [algo.name for algo in sig.preferred_compression_algorithms]

            if prefs:
                key_info["Primary Key"]["Preferences"] = prefs

        break  # Only parse first UID for simplicity

    # Subkey parsing
    for subkey_id, subkey in key.subkeys.items():
        is_revoked = getattr(subkey, "is_revoked", False)
        subinfo = {
            "Fingerprint": subkey.fingerprint,
            "Key ID": subkey.fingerprint[-16:],
            "Key Algorithm": str(subkey.key_algorithm),
            "Created": str(subkey.created),
            "Expires": str(subkey.expires_at) if subkey.expires_at else "Never",
            "Key Size": subkey.key_size,
            "Is Revoked": is_revoked,
            "Capabilities": "Unknown"
        }

        sig = getattr(subkey, "_key_selfsig", None)
        if sig and hasattr(sig, "key_flags") and sig.key_flags:
            subinfo["Capabilities"] = ", ".join(flag.name for flag in sig.key_flags)

        key_info["Subkeys"].append(subinfo)

    return key_info


# CLI wrapper
if __name__ == "__main__":
    email = input("Enter ProtonMail address: ")
    result = get_and_parse_protonmail_key(email)
    pprint(result)

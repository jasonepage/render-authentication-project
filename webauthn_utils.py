import base64
import hashlib
import json
import secrets
import traceback

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from db_utils import get_db_connection


def generate_challenge():
    random_bytes = secrets.token_bytes(32)
    return bytes_to_base64url(random_bytes)


def base64url_to_bytes(base64url):
    padded = base64url + "=" * (4 - len(base64url) % 4)
    standard = padded.replace("-", "+").replace("_", "/")
    return base64.b64decode(standard)


def bytes_to_base64url(bytes_value):
    base64_str = base64.b64encode(bytes_value).decode("ascii")
    return base64_str.replace("+", "-").replace("/", "_").rstrip("=")


def normalize_credential_id(credential_id):
    standard_format = credential_id.replace("-", "+").replace("_", "/")
    return standard_format.replace("+", "-").replace("/", "_").replace("=", "")


def extract_attestation_info(attestation_object_base64):
    try:
        attestation_object = base64url_to_bytes(attestation_object_base64)
        attestation_data = cbor2.loads(attestation_object)

        auth_data_bytes = attestation_data.get("authData", b"")
        aaguid_bytes = None

        aaguid = None
        if len(auth_data_bytes) >= 53:
            aaguid_bytes = auth_data_bytes[37:53]
            aaguid = bytes_to_base64url(aaguid_bytes)

            if aaguid == "AAAAAAAAAAAAAAAAAAAAAA":
                try:
                    statement = attestation_data.get("attStmt", {})
                    fmt = attestation_data.get("fmt", "")

                    if fmt == "packed" and "x5c" in statement:
                        cert_data = statement["x5c"][0] if statement.get("x5c") else None
                        if cert_data:
                            cert_hash = hashlib.sha256(cert_data).hexdigest()
                            aaguid = f"identiv-{cert_hash[:16]}"
                except Exception:
                    pass

        attestation_hash = hashlib.sha256(attestation_object).hexdigest()
        statement = attestation_data.get("attStmt", {})

        key_fingerprint = None
        if statement.get("x5c"):
            try:
                cert_data = statement["x5c"][0]
                key_fingerprint = hashlib.sha256(cert_data).hexdigest()
            except Exception:
                pass

        flags_byte = auth_data_bytes[32] if len(auth_data_bytes) > 32 else 0
        resident_key = bool(flags_byte & 0x40)

        combined_key_hash = key_fingerprint
        if not combined_key_hash and aaguid_bytes and "sig" in statement:
            combined_key_hash = hashlib.sha256(aaguid_bytes + statement["sig"]).hexdigest()

        return (aaguid, attestation_hash, combined_key_hash, resident_key)
    except Exception:
        print(traceback.format_exc())
        return (None, None, None, False)


def find_existing_user_by_credential_id(credential_id):
    if not credential_id:
        return None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        normalized_id = normalize_credential_id(credential_id)
        cursor.execute("SELECT user_id FROM security_keys WHERE credential_id = ?", (normalized_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception:
        print(traceback.format_exc())
        return None


def find_existing_user_by_key(aaguid, public_key_pem, combined_key_hash=None):
    if not aaguid and not combined_key_hash:
        return None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if combined_key_hash:
            cursor.execute(
                "SELECT user_id FROM security_keys WHERE combined_key_hash = ?",
                (combined_key_hash,),
            )
            result = cursor.fetchone()
            if result:
                conn.close()
                return result[0]

        if aaguid:
            cursor.execute("SELECT DISTINCT user_id FROM security_keys WHERE aaguid = ?", (aaguid,))
            user_ids = [row[0] for row in cursor.fetchall()]
            if len(user_ids) == 1:
                conn.close()
                return user_ids[0]

            if public_key_pem:
                cursor.execute("SELECT user_id, public_key FROM security_keys WHERE aaguid = ?", (aaguid,))
                results = cursor.fetchall()

                for user_id, stored_key_json in results:
                    try:
                        stored_key = json.loads(stored_key_json)
                        if stored_key.get("publicKey") == public_key_pem:
                            conn.close()
                            return user_id
                    except Exception:
                        continue

        conn.close()
        return None
    except Exception:
        print(traceback.format_exc())
        return None


def extract_public_key_from_attestation(attestation_object):
    decoded = cbor2.loads(base64url_to_bytes(attestation_object))
    auth_data = decoded["authData"]

    pos = 37
    cred_data_length = len(auth_data[pos:])
    if cred_data_length > 0:
        cred_id_len = int.from_bytes(auth_data[pos + 16 : pos + 18], "big")
        pos += 18 + cred_id_len
        cose_key = cbor2.loads(auth_data[pos:])

        if cose_key[3] == -7:
            x = cose_key[-2]
            y = cose_key[-3]
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x, "big"),
                y=int.from_bytes(y, "big"),
                curve=ec.SECP256R1(),
            )
            public_key = public_numbers.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode("ascii")

        raise ValueError(f"Unsupported algorithm: {cose_key[3]}")

    raise ValueError("Missing credential data in attestation")


def verify_authenticator_signature(public_key_data, client_data_hash, authenticator_data, signature):
    try:
        stored_key = json.loads(public_key_data)
        signed_data = authenticator_data + client_data_hash
        public_key = serialization.load_pem_public_key(stored_key["publicKey"].encode())

        try:
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    except Exception:
        print(traceback.format_exc())
        return False

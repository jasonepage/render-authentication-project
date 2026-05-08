"""
Demo blueprint — ephemeral, fully decoded WebAuthn walkthrough.

Mirrors the real register/login flow but:
  - Persists nothing (state lives in the session under demo_* keys).
  - Accepts any authenticator (passkeys + cross-platform).
  - Returns a rich `breakdown` payload alongside each response so the
    frontend can render the actual bytes flowing across the wire.
"""

import hashlib
import json
import secrets
import traceback

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from flask import Blueprint, jsonify, request, session

from webauthn_utils import (
    base64url_to_bytes,
    bytes_to_base64url,
    normalize_credential_id,
)

demo_bp = Blueprint("demo", __name__, url_prefix="/demo")


# COSE key parameter labels (subset of RFC 8152)
COSE_KTY = {1: "OKP", 2: "EC2", 3: "RSA"}
COSE_ALG = {-7: "ES256", -8: "EdDSA", -35: "ES384", -36: "ES512", -257: "RS256"}
COSE_CRV = {1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519", 7: "Ed448"}


def _hex(b: bytes) -> str:
    return b.hex()


def _format_aaguid(aaguid_bytes: bytes) -> str:
    """16 raw bytes → canonical UUID string."""
    if len(aaguid_bytes) != 16:
        return _hex(aaguid_bytes)
    h = aaguid_bytes.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _decode_flags(flags_byte: int) -> dict:
    """Authenticator data flags byte (RFC 8152 §6.1)."""
    return {
        "raw": f"0b{flags_byte:08b}",
        "UP": bool(flags_byte & 0x01),  # User present
        "UV": bool(flags_byte & 0x04),  # User verified
        "BE": bool(flags_byte & 0x08),  # Backup eligible
        "BS": bool(flags_byte & 0x10),  # Backup state
        "AT": bool(flags_byte & 0x40),  # Attested credential data included
        "ED": bool(flags_byte & 0x80),  # Extension data included
    }


def _decode_authenticator_data(auth_data: bytes) -> dict:
    """Parse the authenticatorData byte string into its named fields."""
    result = {
        "totalLength": len(auth_data),
        "rpIdHash": _hex(auth_data[0:32]),
    }

    if len(auth_data) < 37:
        return result

    flags_byte = auth_data[32]
    result["flagsByte"] = f"0x{flags_byte:02x}"
    result["flags"] = _decode_flags(flags_byte)
    result["signCount"] = int.from_bytes(auth_data[33:37], "big")

    pos = 37
    if flags_byte & 0x40 and len(auth_data) > pos + 18:
        aaguid_bytes = auth_data[pos : pos + 16]
        cred_id_len = int.from_bytes(auth_data[pos + 16 : pos + 18], "big")
        cred_id = auth_data[pos + 18 : pos + 18 + cred_id_len]

        result["attestedCredentialData"] = {
            "aaguid": _format_aaguid(aaguid_bytes),
            "credentialIdLength": cred_id_len,
            "credentialId": bytes_to_base64url(cred_id),
        }

        pos = pos + 18 + cred_id_len
        try:
            cose_key = cbor2.loads(auth_data[pos:])
            result["attestedCredentialData"]["credentialPublicKey"] = _decode_cose_key(cose_key)
        except Exception as e:
            result["attestedCredentialData"]["credentialPublicKey"] = {"error": str(e)}

    return result


def _decode_cose_key(cose_key: dict) -> dict:
    """Decode a COSE_Key map into a human-readable dict."""
    kty = cose_key.get(1)
    alg = cose_key.get(3)
    out = {
        "kty": f"{kty} ({COSE_KTY.get(kty, 'unknown')})",
        "alg": f"{alg} ({COSE_ALG.get(alg, 'unknown')})",
    }

    if kty == 2:  # EC2
        crv = cose_key.get(-1)
        x = cose_key.get(-2, b"")
        y = cose_key.get(-3, b"")
        out["crv"] = f"{crv} ({COSE_CRV.get(crv, 'unknown')})"
        out["x"] = _hex(x)
        out["y"] = _hex(y)
    elif kty == 1:  # OKP (Ed25519)
        crv = cose_key.get(-1)
        x = cose_key.get(-2, b"")
        out["crv"] = f"{crv} ({COSE_CRV.get(crv, 'unknown')})"
        out["x"] = _hex(x)
    elif kty == 3:  # RSA
        n = cose_key.get(-1, b"")
        e = cose_key.get(-2, b"")
        out["n_length_bits"] = len(n) * 8
        out["e"] = _hex(e)

    return out


def _cose_key_to_pem(cose_key):
    """Build a PEM-encoded SubjectPublicKeyInfo from a COSE_Key map."""
    kty = cose_key.get(1)

    if kty == 2:  # EC2
        crv = cose_key.get(-1)
        x = int.from_bytes(cose_key[-2], "big")
        y = int.from_bytes(cose_key[-3], "big")
        curve = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}.get(crv)
        if curve is None:
            return None
        public_key = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()
    elif kty == 3:  # RSA
        n = int.from_bytes(cose_key[-1], "big")
        e = int.from_bytes(cose_key[-2], "big")
        public_key = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    else:
        return None

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _verify_signature(public_key_pem: str, signed_data: bytes, signature: bytes, alg: int) -> bool:
    """Verify an authenticator signature against the stored public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        if alg == -7:
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        elif alg == -257:
            public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        elif alg == -8:
            public_key.verify(signature, signed_data)
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _rp_id_for(host: str) -> str:
    hostname = host.split(":")[0]
    return hostname  # localhost or actual host — same as production for the demo


# ---------------------------------------------------------------------------
# Registration walkthrough
# ---------------------------------------------------------------------------


@demo_bp.route("/register/options", methods=["POST"])
def demo_register_options():
    try:
        challenge_bytes = secrets.token_bytes(32)
        challenge_b64url = bytes_to_base64url(challenge_bytes)

        user_id_bytes = secrets.token_bytes(16)
        user_id_b64url = bytes_to_base64url(user_id_bytes)

        session["demo_challenge"] = challenge_b64url
        session["demo_user_id"] = user_id_b64url

        rp_id = _rp_id_for(request.host)

        options = {
            "challenge": challenge_b64url,
            "rp": {"name": "Auth Chat — Demo", "id": rp_id},
            "user": {
                "id": user_id_b64url,
                "name": f"demo-{user_id_b64url[:6]}",
                "displayName": f"Demo User {user_id_b64url[:6]}",
            },
            # Allow ES256 (most common) and RS256 for broader passkey compatibility
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            # Demo-only: no attachment restriction. Accepts platform authenticators
            # (Touch ID, Windows Hello, Android biometric) AND cross-platform keys.
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred",
            },
            "timeout": 120000,
            "attestation": "none",
        }

        return jsonify({
            "options": options,
            "breakdown": {
                "challenge": {
                    "purpose": "32 random bytes the client must echo back, signed. Prevents replay.",
                    "rawHex": _hex(challenge_bytes),
                    "rawBase64url": challenge_b64url,
                    "length": len(challenge_bytes),
                },
                "userId": {
                    "purpose": "Random opaque user handle. Not derived from any PII.",
                    "rawHex": _hex(user_id_bytes),
                    "rawBase64url": user_id_b64url,
                },
                "rpId": {
                    "purpose": "Relying Party ID. Must match the page's effective domain.",
                    "value": rp_id,
                },
                "pubKeyCredParams": {
                    "purpose": "Algorithms the server accepts, in preference order.",
                    "decoded": [
                        {"alg": -7, "name": "ES256 (ECDSA w/ SHA-256, P-256)"},
                        {"alg": -257, "name": "RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)"},
                    ],
                },
            },
        })
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@demo_bp.route("/register/verify", methods=["POST"])
def demo_register_verify():
    try:
        data = request.get_json()
        if not data or not data.get("response"):
            return jsonify({"error": "Missing credential response"}), 400

        stored_challenge = session.get("demo_challenge")
        if not stored_challenge:
            return jsonify({"error": "No demo challenge in session — start over"}), 400

        credential_id = data.get("id")
        client_data_json_b64 = data["response"]["clientDataJSON"]
        attestation_object_b64 = data["response"]["attestationObject"]

        client_data_bytes = base64url_to_bytes(client_data_json_b64)
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        attestation_bytes = base64url_to_bytes(attestation_object_b64)
        attestation = cbor2.loads(attestation_bytes)
        auth_data_bytes = attestation.get("authData", b"")

        auth_data_decoded = _decode_authenticator_data(auth_data_bytes)

        # Extract public key for the auth-walkthrough step
        public_key_pem = None
        cose_key_decoded = None
        cred_alg = None
        if auth_data_decoded.get("attestedCredentialData"):
            pos = 37 + 18 + auth_data_decoded["attestedCredentialData"]["credentialIdLength"]
            cose_key = cbor2.loads(auth_data_bytes[pos:])
            cose_key_decoded = _decode_cose_key(cose_key)
            cred_alg = cose_key.get(3)
            try:
                public_key_pem = _cose_key_to_pem(cose_key)
            except Exception as pem_err:
                cose_key_decoded["pemError"] = str(pem_err)

        # Verification checks (mirror real auth.py logic)
        challenge_match = client_data.get("challenge") == stored_challenge
        type_match = client_data.get("type") == "webauthn.create"
        origin = client_data.get("origin", "")
        expected_origin = request.host_url.rstrip("/")
        # Be lenient about scheme for localhost dev
        origin_match = origin in (
            expected_origin,
            expected_origin.replace("http://", "https://"),
            expected_origin.replace("https://", "http://"),
        )

        verified = challenge_match and type_match and origin_match

        if verified and public_key_pem:
            session["demo_credential_id"] = normalize_credential_id(credential_id)
            session["demo_public_key"] = public_key_pem
            session["demo_alg"] = cred_alg

        return jsonify({
            "verified": verified,
            "credentialId": credential_id,
            "breakdown": {
                "clientDataJSON": {
                    "purpose": "Browser-built JSON proving what the user agreed to. Signed by the authenticator.",
                    "rawBase64url": client_data_json_b64,
                    "rawLength": len(client_data_bytes),
                    "decoded": client_data,
                },
                "attestationObject": {
                    "purpose": "CBOR-encoded blob containing the new credential and (optionally) attestation proof.",
                    "rawBase64url": attestation_object_b64,
                    "rawLength": len(attestation_bytes),
                    "decoded": {
                        "fmt": attestation.get("fmt"),
                        "attStmt": {
                            k: (
                                _hex(v) if isinstance(v, (bytes, bytearray))
                                else [_hex(b) if isinstance(b, (bytes, bytearray)) else b for b in v]
                                if isinstance(v, list)
                                else v
                            )
                            for k, v in (attestation.get("attStmt") or {}).items()
                        },
                        "authData": auth_data_decoded,
                    },
                },
                "extractedPublicKey": {
                    "purpose": "COSE_Key from authData converted to a standard PEM the server stores.",
                    "cose": cose_key_decoded,
                    "pem": public_key_pem,
                },
                "verificationChecks": {
                    "challengeMatches": {
                        "passed": challenge_match,
                        "expected": stored_challenge,
                        "received": client_data.get("challenge"),
                    },
                    "typeMatches": {
                        "passed": type_match,
                        "expected": "webauthn.create",
                        "received": client_data.get("type"),
                    },
                    "originMatches": {
                        "passed": origin_match,
                        "expected": expected_origin,
                        "received": origin,
                    },
                    "result": "VERIFIED — credential would be persisted in production" if verified else "REJECTED",
                },
                "ephemeralNote": "This walkthrough does not write to the database. The credential lives in your session for the auth step, then disappears.",
            },
        })
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Authentication walkthrough
# ---------------------------------------------------------------------------


@demo_bp.route("/auth/options", methods=["POST"])
def demo_auth_options():
    try:
        if "demo_credential_id" not in session:
            return jsonify({
                "error": "No demo credential — run the registration walkthrough first."
            }), 400

        challenge_bytes = secrets.token_bytes(32)
        challenge_b64url = bytes_to_base64url(challenge_bytes)
        session["demo_challenge"] = challenge_b64url

        rp_id = _rp_id_for(request.host)
        credential_id = session["demo_credential_id"]

        options = {
            "challenge": challenge_b64url,
            "timeout": 60000,
            "rpId": rp_id,
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": credential_id,
                    "transports": ["usb", "nfc", "ble", "internal", "hybrid"],
                }
            ],
            "userVerification": "preferred",
        }

        return jsonify({
            "options": options,
            "breakdown": {
                "challenge": {
                    "purpose": "Fresh 32-byte challenge for this assertion. Different from the registration challenge.",
                    "rawHex": _hex(challenge_bytes),
                    "rawBase64url": challenge_b64url,
                },
                "rpId": {
                    "purpose": "Relying Party ID — the authenticator will only sign for credentials registered under this ID.",
                    "value": rp_id,
                },
                "allowCredentials": {
                    "purpose": "Tells the browser which credential(s) to use. Single entry here = the one you just registered.",
                    "credentialIds": [credential_id],
                },
            },
        })
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@demo_bp.route("/auth/verify", methods=["POST"])
def demo_auth_verify():
    try:
        data = request.get_json()
        if not data or not data.get("response"):
            return jsonify({"error": "Missing assertion response"}), 400

        stored_challenge = session.get("demo_challenge")
        public_key_pem = session.get("demo_public_key")
        alg = session.get("demo_alg") or -7
        if not stored_challenge or not public_key_pem:
            return jsonify({"error": "Demo session expired — start over"}), 400

        client_data_json_b64 = data["response"]["clientDataJSON"]
        authenticator_data_b64 = data["response"]["authenticatorData"]
        signature_b64 = data["response"]["signature"]

        client_data_bytes = base64url_to_bytes(client_data_json_b64)
        client_data = json.loads(client_data_bytes.decode("utf-8"))

        authenticator_data_bytes = base64url_to_bytes(authenticator_data_b64)
        signature_bytes = base64url_to_bytes(signature_b64)

        auth_data_decoded = _decode_authenticator_data(authenticator_data_bytes)

        challenge_match = client_data.get("challenge") == stored_challenge
        type_match = client_data.get("type") == "webauthn.get"

        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        signed_data = authenticator_data_bytes + client_data_hash
        signature_valid = _verify_signature(public_key_pem, signed_data, signature_bytes, alg)

        verified = challenge_match and type_match and signature_valid

        return jsonify({
            "verified": verified,
            "breakdown": {
                "clientDataJSON": {
                    "purpose": "Browser-built JSON for this assertion. Hashed and concatenated with authenticatorData before signing.",
                    "rawBase64url": client_data_json_b64,
                    "decoded": client_data,
                },
                "authenticatorData": {
                    "purpose": "Authenticator-emitted bytes (rpIdHash + flags + signCount). Concatenated with the clientData hash to form the signed payload.",
                    "rawBase64url": authenticator_data_b64,
                    "rawLength": len(authenticator_data_bytes),
                    "decoded": auth_data_decoded,
                },
                "signature": {
                    "purpose": "ECDSA signature over authenticatorData + SHA-256(clientDataJSON), produced inside the authenticator. The private key never leaves the device.",
                    "rawBase64url": signature_b64,
                    "rawHex": _hex(signature_bytes),
                    "length": len(signature_bytes),
                },
                "signedData": {
                    "purpose": "What the authenticator actually signed: authenticatorData ‖ SHA-256(clientDataJSON).",
                    "clientDataHashHex": _hex(client_data_hash),
                    "totalLength": len(signed_data),
                },
                "verificationChecks": {
                    "challengeMatches": {
                        "passed": challenge_match,
                        "expected": stored_challenge,
                        "received": client_data.get("challenge"),
                    },
                    "typeMatches": {
                        "passed": type_match,
                        "expected": "webauthn.get",
                        "received": client_data.get("type"),
                    },
                    "signatureValid": {
                        "passed": signature_valid,
                        "algorithm": COSE_ALG.get(alg, str(alg)),
                    },
                    "result": "VERIFIED — user would be logged in" if verified else "REJECTED",
                },
            },
        })
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@demo_bp.route("/reset", methods=["POST"])
def demo_reset():
    """Clear demo session state without touching real auth state."""
    for key in ("demo_challenge", "demo_user_id", "demo_credential_id", "demo_public_key", "demo_alg"):
        session.pop(key, None)
    return jsonify({"status": "reset"})

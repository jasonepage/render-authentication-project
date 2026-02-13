import base64
import hashlib
import json
import secrets
import traceback

from flask import Blueprint, jsonify, request, session

from db_utils import can_register, get_db_connection, get_total_users
from webauthn_utils import (
    extract_attestation_info,
    extract_public_key_from_attestation,
    find_existing_user_by_credential_id,
    find_existing_user_by_key,
    generate_challenge,
    normalize_credential_id,
    verify_authenticator_signature,
    base64url_to_bytes,
    bytes_to_base64url,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register_options", methods=["POST"])
def webauthn_register_options():
    try:
        # Check if user is authenticated and allowed to register
        is_authenticated = session.get("authenticated", False)
        user_id = session.get("user_id", None) if is_authenticated else None
        
        # If user is authenticated, only allow if they're admin
        if is_authenticated and user_id:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT is_admin FROM security_keys WHERE user_id = ?", (user_id,))
                result = cursor.fetchone()
                conn.close()
                
                if not result or not bool(result[0]):
                    return jsonify({"error": "Only administrators can register new keys"}), 403
            except Exception as e:
                print(f"Error checking admin status: {e}")
                return jsonify({"error": "Failed to verify admin status"}), 500
        
        # Check if registration is globally enabled (unless it's first registration)
        can_reg, error_msg = can_register()
        if not can_reg:
            # Allow registration for admins or if no users exist yet
            total_users = get_total_users()
            if total_users > 0 and not (is_authenticated and user_id):
                return jsonify({"error": error_msg}), 403

        total_users = get_total_users()

        user_id_raw = secrets.token_bytes(16)
        user_id = bytes_to_base64url(user_id_raw)
        session["user_id_for_registration"] = user_id

        challenge = generate_challenge().rstrip("=")
        session["challenge"] = challenge

        try:
            base64.b64decode(
                challenge.replace("-", "+").replace("_", "/")
                + "=" * (4 - len(challenge) % 4)
            )
        except Exception:
            pass

        host = request.host
        hostname = host.split(":")[0]

        if hostname != "localhost" and hostname != "127.0.0.1":
            rp_id = "render-authentication-project.onrender.com"
        else:
            rp_id = hostname

        options = {
            "challenge": challenge,
            "rp": {"name": "FIDO2 Chat System", "id": rp_id},
            "user": {
                "id": user_id,
                "name": f"User-{user_id[:6]}",
                "displayName": f"User {user_id[:6]}",
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "requireResidentKey": True,
                "residentKey": "required",
                "userVerification": "discouraged",
            },
            "timeout": 120000,
            "attestation": "none",
        }

        return jsonify(options)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/register_complete", methods=["POST"])
def webauthn_register_complete():
    try:
        data = request.get_json()
        credential_id = data.get("id")
        if not credential_id:
            return jsonify({"error": "No credential ID in response"}), 400

        if "user_id_for_registration" not in session:
            return jsonify({"error": "Registration session expired"}), 400

        user_id = session["user_id_for_registration"]

        if (
            not data.get("response")
            or not data["response"].get("clientDataJSON")
            or not data["response"].get("attestationObject")
        ):
            return jsonify({"error": "Invalid attestation data"}), 400

        attestation_object = data["response"]["attestationObject"]
        aaguid, attestation_hash, combined_key_hash, resident_key = extract_attestation_info(
            attestation_object
        )

        if aaguid:
            platform_aaguids = [
                "adce0002-35bc-c60a-648b-0b25f1f05503",
                "08987058-cadc-4b81-b6e1-30de50dcbe96",
                "9ddd1817-af5a-4672-a2b9-3e3dd95000a9",
                "6028b017-b1d4-4c02-b4b3-afcdafc96bb2",
                "dd4ec289-e01d-41c9-bb89-70fa845d4bf2",
                "39a5647e-1853-446c-a1f6-a79bae9f5bc7",
            ]
            aaguid_normalized = aaguid.lower().replace("-", "")
            for platform_guid in platform_aaguids:
                if aaguid_normalized == platform_guid.lower().replace("-", ""):
                    return (
                        jsonify(
                            {
                                "error": "Platform authenticators are not allowed. Please use a physical security key."
                            }
                        ),
                        403,
                    )

        public_key_pem = extract_public_key_from_attestation(attestation_object)
        normalized_credential_id = normalize_credential_id(credential_id)

        existing_user_id = find_existing_user_by_credential_id(normalized_credential_id)
        if existing_user_id:
            session["authenticated"] = True
            session["user_id"] = existing_user_id
            session.pop("user_id_for_registration", None)
            return jsonify(
                {
                    "status": "existing_key",
                    "message": "This credential is already registered",
                    "userId": existing_user_id,
                }
            )

        if combined_key_hash:
            existing_user_by_key = find_existing_user_by_key(
                aaguid, public_key_pem, combined_key_hash
            )
            if existing_user_by_key:
                conn = get_db_connection()
                cursor = conn.cursor()

                public_key = json.dumps(
                    {
                        "id": credential_id,
                        "type": data.get("type", "public-key"),
                        "publicKey": public_key_pem,
                        "attestation": {
                            "clientDataJSON": data["response"]["clientDataJSON"],
                            "attestationObject": data["response"]["attestationObject"],
                        },
                    }
                )

                cursor.execute(
                    """
                    INSERT INTO security_keys
                        (credential_id, user_id, public_key, aaguid, attestation_hash,
                         combined_key_hash, resident_key, created_at, is_admin)
                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), 0)
                    """,
                    (
                        normalized_credential_id,
                        existing_user_by_key,
                        public_key,
                        aaguid,
                        attestation_hash,
                        combined_key_hash,
                        resident_key,
                    ),
                )

                conn.commit()
                conn.close()

                session["authenticated"] = True
                session["user_id"] = existing_user_by_key
                session.pop("user_id_for_registration", None)

                return jsonify(
                    {
                        "status": "credential_added",
                        "message": "New device credential added to your existing account",
                        "userId": existing_user_by_key,
                    }
                )

        public_key = json.dumps(
            {
                "id": credential_id,
                "type": data.get("type", "public-key"),
                "publicKey": public_key_pem,
                "attestation": {
                    "clientDataJSON": data["response"]["clientDataJSON"],
                    "attestationObject": data["response"]["attestationObject"],
                },
            }
        )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_keys")
        user_count = cursor.fetchone()[0]
        is_admin = user_count == 0

        cursor.execute(
            """
            INSERT INTO security_keys
                (credential_id, user_id, public_key, aaguid, attestation_hash,
                 combined_key_hash, resident_key, created_at, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
            """,
            (
                normalized_credential_id,
                user_id,
                public_key,
                aaguid,
                attestation_hash,
                combined_key_hash,
                resident_key,
                is_admin,
            ),
        )

        conn.commit()
        conn.close()

        session["authenticated"] = True
        session["user_id"] = user_id
        session.pop("user_id_for_registration", None)

        return jsonify({"status": "success", "userId": user_id})
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/login_options", methods=["POST"])
def webauthn_login_options():
    try:
        challenge = generate_challenge()
        session["challenge"] = challenge

        host = request.host
        hostname = host.split(":")[0]
        if hostname != "localhost" and hostname != "127.0.0.1":
            rp_id = "render-authentication-project.onrender.com"
        else:
            rp_id = hostname

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT credential_id FROM security_keys")
        credentials = cursor.fetchall()
        conn.close()

        allowed_credentials = [
            {
                "type": "public-key",
                "id": credential_id,
                "transports": ["usb", "nfc", "ble", "internal", "hybrid"],
            }
            for (credential_id,) in credentials
        ]

        options = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": rp_id,
            "allowCredentials": allowed_credentials,
            "userVerification": "discouraged",
        }

        return jsonify(options)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/login_complete", methods=["POST"])
def webauthn_login_complete():
    try:
        data = request.get_json()
        credential_id = data.get("id")
        if not credential_id:
            return jsonify({"error": "No credential ID provided"}), 400

        stored_challenge = session.get("challenge")
        if not stored_challenge:
            return jsonify(
                {"error": "No challenge found in session. Please try again."}
            ), 400

        if not data.get("response") or not data["response"].get("clientDataJSON"):
            return jsonify({"error": "Missing clientDataJSON"}), 400

        client_data_json_b64 = data["response"]["clientDataJSON"]
        client_data_json = base64url_to_bytes(client_data_json_b64)

        authenticator_data = base64url_to_bytes(data["response"]["authenticatorData"])
        signature = base64url_to_bytes(data["response"]["signature"])

        try:
            client_data = json.loads(client_data_json.decode("utf-8"))
            response_challenge = client_data.get("challenge")
            if response_challenge != stored_challenge:
                return jsonify({"error": "Challenge verification failed"}), 400

            if client_data.get("type") != "webauthn.get":
                return jsonify({"error": "Invalid type"}), 400

            origin = client_data.get("origin", "")
            expected_domain = "render-authentication-project.onrender.com"
            if (
                expected_domain not in origin
                and "localhost" not in origin
                and "127.0.0.1" not in origin
            ):
                return jsonify({"error": "Invalid origin"}), 400
        except Exception as e:
            return jsonify({"error": f"Failed to parse client data: {e}"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        normalized_credential_id = normalize_credential_id(credential_id)
        cursor.execute(
            "SELECT user_id, public_key FROM security_keys WHERE credential_id = ?",
            (normalized_credential_id,),
        )
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                "SELECT user_id, public_key FROM security_keys WHERE credential_id = ?",
                (credential_id,),
            )
            row = cursor.fetchone()

        conn.close()

        if not row:
            return jsonify({"error": "Unknown credential"}), 400

        user_id = row[0]
        public_key_data = row[1]

        client_data_hash = hashlib.sha256(client_data_json).digest()
        if not verify_authenticator_signature(
            public_key_data, client_data_hash, authenticator_data, signature
        ):
            return jsonify({"error": "Invalid signature"}), 400

        session["authenticated"] = True
        session["user_id"] = user_id

        return jsonify({"status": "success", "userId": user_id})
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@auth_bp.route("/logout", methods=["POST"])
def webauthn_logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"})


@auth_bp.route("/auth_status", methods=["GET"])
def webauthn_auth_status():
    is_authenticated = session.get("authenticated", False)
    user_id = session.get("user_id", None) if is_authenticated else None
    username = None
    is_admin = False
    registration_enabled = True

    if is_authenticated and user_id:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, is_admin FROM security_keys WHERE user_id = ?",
                (user_id,),
            )
            result = cursor.fetchone()

            if result:
                username = result[0] if result[0] else f"User-{user_id[:6]}"
                is_admin = bool(result[1])
            else:
                username = f"User-{user_id[:6]}"

            cursor.execute(
                "SELECT registration_enabled FROM registration_settings WHERE id = 1"
            )
            reg_result = cursor.fetchone()
            if reg_result:
                registration_enabled = bool(reg_result[0])

            conn.close()
        except Exception:
            username = f"User-{user_id[:6]}"
    else:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT registration_enabled FROM registration_settings WHERE id = 1"
            )
            reg_result = cursor.fetchone()
            if reg_result:
                registration_enabled = bool(reg_result[0])
            conn.close()
        except Exception:
            pass

    return jsonify(
        {
            "authenticated": is_authenticated,
            "userId": user_id,
            "username": username,
            "isAdmin": is_admin,
            "registrationEnabled": registration_enabled,
        }
    )


@auth_bp.route("/check_registration_status", methods=["GET"])
def check_registration_status():
    can_reg, error_msg = can_register()
    total_users = get_total_users()

    return jsonify(
        {
            "canRegister": can_reg,
            "totalUsers": total_users,
            "remainingSlots": max(0, 25 - total_users),
            "message": error_msg if not can_reg else f"{total_users}/25 users registered",
        }
    )



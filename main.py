import os
from flask import Flask, request, Response, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB


@app.get("/")
def index():
    return jsonify({
        "service": "Moodle decypher service",
        "endpoints": {
            "GET /login": "returns the configured Moodle login",
            "POST /decypher": "multipart/form-data fields: key and secret"
        }
    })


@app.get("/login")
def login():
    value = os.environ.get("MOODLE_LOGIN", "").strip()
    if not value:
        return Response("MOODLE_LOGIN is not configured", status=503, mimetype="text/plain")
    return Response(value, mimetype="text/plain; charset=utf-8")


@app.post("/decypher")
def decypher():
    key_file = request.files.get("key")
    secret_file = request.files.get("secret")
    if key_file is None or secret_file is None:
        return Response("Required multipart fields: key and secret", status=400,
                        mimetype="text/plain")

    key_data = key_file.read()
    ciphertext = secret_file.read()
    if not key_data or not ciphertext:
        return Response("The key and secret files must not be empty", status=400,
                        mimetype="text/plain")

    try:
        private_key = load_pem_private_key(key_data, password=None)
        if not hasattr(private_key, "decrypt"):
            raise ValueError("The supplied key is not an RSA private key")

        # Try the common RSA padding variants used by OpenSSL and web exercises.
        paddings = [
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None),
            padding.PKCS1v15(),
        ]
        last_error = None
        for pad in paddings:
            try:
                plaintext = private_key.decrypt(ciphertext, pad)
                return Response(plaintext, mimetype="text/plain; charset=utf-8")
            except Exception as exc:
                last_error = exc
        raise ValueError("Decryption failed: unsupported ciphertext or RSA padding") from last_error

    except Exception as exc:
        # Do not expose private-key material or internal tracebacks to clients.
        message = str(exc) if isinstance(exc, ValueError) else "Invalid private key or ciphertext"
        return Response(message, status=400, mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3001"))
    app.run(host="0.0.0.0", port=port)

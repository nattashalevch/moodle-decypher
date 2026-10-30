# Moodle Decypher Web App

## Replit deployment
1. Create a new Python Replit project and upload these files (or import this ZIP).
2. In **Tools → Secrets** add `MOODLE_LOGIN` with your actual Moodle username.
3. Run the project. Replit will provide an HTTPS URL.
4. Submit the root URL (without `/decypher` or `/login`).

## API
- `GET /login` — returns `MOODLE_LOGIN` as plain text.
- `POST /decypher` — accepts `multipart/form-data` fields named `key` and `secret`.
  The `key` file must be an unencrypted PEM RSA private key; `secret` must contain
  raw RSA ciphertext. The server tries OAEP-SHA256, OAEP-SHA1, and PKCS#1 v1.5.

The application deliberately does not log uploaded key or ciphertext contents.

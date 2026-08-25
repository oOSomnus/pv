# Encrypt the vault payload with Argon2id and AES-256-GCM

The vault stores its credential entries as an encrypted payload. We derive the encryption key from the master password with Argon2id and encrypt the payload with AES-256-GCM, using a vault salt and a fresh nonce for every save. This keeps credential values out of the file at rest and avoids nonce reuse while retaining the existing cryptographic dependencies and versioned file envelope.

## Consequences

- Opening a vault requires the correct master password.
- Every successful mutation rewrites the encrypted payload with a new nonce.
- A lost master password cannot be recovered by the application.

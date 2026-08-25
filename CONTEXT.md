# PV

PV manages website credentials as encrypted vaults. This context defines the vocabulary used by the interactive credential manager.

## Credential entries

**Vault**:
An encrypted collection of credential entries unlocked by a master password.

**Key**:
The website or service identifier used to locate a credential entry, such as `youtube`.
_Avoid_: Name

**Name**:
The username or login identity associated with a key.
_Avoid_: Key

**Value**:
The password or other secret associated with a key and name.
_Avoid_: Key, Name

**Master password**:
The password that unlocks a vault; it is separate from every credential value stored in that vault.

**Credential entry**:
A record identified by a key and containing the associated name and value.

**Generated value**:
A randomly generated credential value produced from a user-selected length and character set before it is confirmed for storage.

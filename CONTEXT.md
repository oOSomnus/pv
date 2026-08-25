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
A randomly generated credential value produced from user-selected generation settings before it is confirmed for storage.

**Symbol set**:
The compatibility characters `!@.-_*` available to a Generated value when symbol generation is enabled. Enabling the Symbol set requires at least one of these characters in the Generated value; it does not validate or restrict a manually entered Value.

## Workflow

**Draft**:
A credential entry being assembled but not yet stored in a Vault. A draft can be revised or abandoned without changing the Vault.

**Back**:
The action that moves from the current workflow step to its immediate parent while retaining the current Draft.

_Avoid_: Cancel

**Cancel**:
The action that abandons the current operation and Draft without persisting changes, returning to Vault navigation.

_Avoid_: Back

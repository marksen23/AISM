# Policy trust anchor (`/etc/aism/trust`)

Two files can live here. The gateway mounts the directory read-only, separate from `policy/`, so whoever can change the policy cannot also change the trust anchor.

**Single signature (threshold 1).** `allowed_signers` (OpenSSH format) lists the public keys allowed to sign `policy/policy.yaml` (namespace `aism-policy`). The gateway (`POLICY_ALLOWED_SIGNERS=/etc/aism/trust/allowed_signers`) refuses an unsigned or invalid signature; the previous policy stays active.

```
policy-signer@example.com namespaces="aism-policy" ssh-ed25519 AAAAC3Nz... policy-signer@example.com
```

**Keyring (K3, threshold 2 by default).** If `keyring.yaml` (and `keyring.yaml.sigs`) is present, it replaces the file above as the trust anchor. It lists signer identities, Ed25519 public keys, roles (`policy`, `keyring`), `notBefore`/`notAfter` and revocation. Changing it requires a quorum of keys that are already valid; one key cannot add itself or remove the others, and an older version is rejected. Policies then use a bundle `policy.yaml.sigs`. Expired, revoked and unknown keys do not count, and the same identity counts once.

Create keys with `tools/aism-policy-sign.py keygen` (or `ssh-keygen -t ed25519`) **outside the repository**, then `init-keyring`. Copy only the public keyring here. **Never** put a private key into this directory or the repository. Commands and limits (no HSM, no transparency log): [`policy/AISM-Policy-Format.md`](../../policy/AISM-Policy-Format.md) §6.2.

# Policy trust anchor (`/etc/aism/trust`)

`allowed_signers` (OpenSSH format) lists the public keys allowed to sign `policy/policy.yaml`
(namespace `aism-policy`). The gateway (`POLICY_ALLOWED_SIGNERS=/etc/aism/trust/allowed_signers`)
refuses unsigned policies and policies with an invalid signature; the previous policy stays active.

```
policy-signer@example.com namespaces="aism-policy" ssh-ed25519 AAAAC3Nz... policy-signer@example.com
```

Create a key pair with `tools/aism-policy-sign.py keygen --out <dir outside the repo> --identity <id>`
(or `ssh-keygen -t ed25519`) and copy only the `allowed_signers` line here. **Never** put a private
key into this directory or the repository. This directory is kept separate from `policy/` so that
whoever can change the policy cannot also change the trust anchor (mount both read-only).

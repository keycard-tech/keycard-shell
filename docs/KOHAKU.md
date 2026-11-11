# kohaku-key encrypted credential export

BIP-85 root material remains on Keycard/Shell. After the user reviews the full
validated derivation paths and approves export, path-specific credentials are
exported encrypted to the receiving host. The host decrypts those credentials;
Groth16 proving remains host-side.

The review derives credential roles from validated paths: secretType 0 is
nullifier, 1 is salt, and 2 is ephemeral signer. Protocol identifiers and the
KKQ3/KKR3 encryption format are unchanged.

Fingerprint comparison is the user’s responsibility. Compare the displayed host
key fingerprint with the intended receiving host before approving. Displaying a
fingerprint alone does not authenticate the host.

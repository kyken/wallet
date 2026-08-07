# Preserve the Wallet SDK API while propagating External Party signing profiles

External Party signing algorithms will be configured on the SDK instance and propagated to key generation, party onboarding, and transaction-signing operations. Individual operations will not accept a separate algorithm override. Existing call shapes and Ed25519 defaults remain compatible through optional SDK configuration, while avoiding algorithm inference from hidden state or opaque party identifiers and preventing a party's public-key type from being paired with the wrong signature metadata.

Both `SDK.create` and `SDK.createOffline` accept the same optional `signingAlgorithm` setting. Omitting it preserves Ed25519 behavior.

The public API exposes the high-level signing algorithm values `ed25519` and `secp256k1`; the SDK owns the mapping to Canton's key specification, signing algorithm, and signature format.

Key pairs continue to be exposed through the existing `publicKey` and `privateKey` string fields. The internal byte encoding may differ by algorithm and will use a Canton-compatible representation rather than forcing secp256k1 material into Ed25519's raw layout.

The Canton `partyId` remains unchanged and does not encode the signing algorithm. Algorithm selection is carried by the SDK instance's explicit `signingAlgorithm` option; putting the algorithm into `partyHint` would only rename the party and would not change Canton signature semantics.

The existing standalone `signTransactionHash` helper remains an Ed25519-only compatibility API and must fail with a clear error when given an unsupported key. A new instance-bound signing method uses the SDK signing configuration for secp256k1 and other supported algorithms.

The SDK will not add a synchronizer capability probe during initialization. It will validate local algorithm/key combinations, submit using the selected Canton metadata, and surface a clear algorithm-specific error if the connected Canton environment rejects the key specification.

The transaction and topology hash computation is unchanged. For `secp256k1`, the signer applies Canton's `EC_DSA_SHA_256` algorithm to the supplied hash bytes and emits a DER-encoded ECDSA signature; the public key is emitted as DER X.509 SubjectPublicKeyInfo.

## Considered Options

- Keep an in-memory profile registry and apply profiles automatically after party creation. Rejected because behavior would depend on SDK instance lifetime and would be implicit after restart.
- Accept a `signingAlgorithm` option on every signing operation. Rejected because repeated algorithm selection is noisy and allows one SDK instance to mix profiles unintentionally.
- Keep Ed25519 hard-coded. Rejected because External Parties backed by signers that only support secp256k1 cannot use the SDK.

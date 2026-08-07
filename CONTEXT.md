# Wallet SDK Signing Context

This context defines the language used for External Party creation and transaction signing in the Wallet SDK.

## Language

**External Party**:
A Canton party whose cryptographic key is controlled outside the participant and whose topology and transaction signatures are supplied by an external signer.

**Signing Profile**:
The signing characteristics associated with an External Party. An SDK instance supplies the profile for key generation and signing operations; individual operations do not select another profile. Signing behavior never depends on algorithm inference from opaque identifiers.

**Signing Algorithm**:
The high-level algorithm choice exposed by the Wallet SDK for an External Party signature, currently `ed25519` or `secp256k1`. The SDK maps this choice to the Canton public-key specification, signature algorithm, and signature format required on the wire.

**SDK Signing Configuration**:
The explicit algorithm configured on an SDK instance. Instance-bound key generation and signing operations use it. When omitted, the SDK preserves the existing Ed25519 behavior. The legacy standalone signing helper remains Ed25519-specific.

`SDK.create` and `SDK.createOffline` accept the same signing configuration so online and offline signing behave consistently.

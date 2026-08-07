// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export type SigningAlgorithm = 'ed25519' | 'secp256k1'

export type CantonSigningProfile = Readonly<{
    publicKeyFormat:
        | 'CRYPTO_KEY_FORMAT_RAW'
        | 'CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO'
    keySpec: 'SIGNING_KEY_SPEC_EC_CURVE25519' | 'SIGNING_KEY_SPEC_EC_SECP256K1'
    signatureFormat: 'SIGNATURE_FORMAT_CONCAT' | 'SIGNATURE_FORMAT_DER'
    signingAlgorithmSpec:
        | 'SIGNING_ALGORITHM_SPEC_ED25519'
        | 'SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256'
}>

const CANTON_SIGNING_PROFILES: Record<SigningAlgorithm, CantonSigningProfile> =
    {
        ed25519: {
            publicKeyFormat: 'CRYPTO_KEY_FORMAT_RAW',
            keySpec: 'SIGNING_KEY_SPEC_EC_CURVE25519',
            signatureFormat: 'SIGNATURE_FORMAT_CONCAT',
            signingAlgorithmSpec: 'SIGNING_ALGORITHM_SPEC_ED25519',
        },
        secp256k1: {
            publicKeyFormat:
                'CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO',
            keySpec: 'SIGNING_KEY_SPEC_EC_SECP256K1',
            signatureFormat: 'SIGNATURE_FORMAT_DER',
            signingAlgorithmSpec: 'SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256',
        },
    }

export const getCantonSigningProfile = (
    signingAlgorithm: SigningAlgorithm = 'ed25519'
): CantonSigningProfile => {
    const profile = CANTON_SIGNING_PROFILES[signingAlgorithm]
    if (!profile) {
        throw new Error(`Unsupported signing algorithm: ${signingAlgorithm}`)
    }
    return profile
}

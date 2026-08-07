// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'

const PRIVATE_KEY_LENGTH = 32
const PUBLIC_KEY_LENGTH = 65

// SubjectPublicKeyInfo for id-ecPublicKey / secp256k1, followed by the
// uncompressed SEC1 public point. Canton expects this DER representation for
// secp256k1 signing keys.
const PUBLIC_KEY_PREFIX = Uint8Array.from([
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
])

const concatBytes = (...parts: Uint8Array[]) => {
    const result = new Uint8Array(
        parts.reduce((length, part) => length + part.length, 0)
    )
    let offset = 0
    for (const part of parts) {
        result.set(part, offset)
        offset += part.length
    }
    return result
}

const toCantonPublicKey = (publicKey: Uint8Array) => {
    if (publicKey.length !== PUBLIC_KEY_LENGTH || publicKey[0] !== 0x04) {
        throw new Error('secp256k1 public key must be an uncompressed point')
    }
    return concatBytes(PUBLIC_KEY_PREFIX, publicKey)
}

const parseCantonPublicKey = (publicKey: Uint8Array) => {
    if (
        publicKey.length !== PUBLIC_KEY_PREFIX.length + PUBLIC_KEY_LENGTH ||
        !PUBLIC_KEY_PREFIX.every((value, index) => value === publicKey[index])
    ) {
        throw new Error(
            'Invalid secp256k1 public key: expected Canton DER X.509 SubjectPublicKeyInfo'
        )
    }
    const point = publicKey.slice(PUBLIC_KEY_PREFIX.length)
    try {
        secp256k1.ProjectivePoint.fromHex(point)
    } catch {
        throw new Error('Invalid secp256k1 public key: point is not on curve')
    }
    return point
}

const validatePrivateKey = (privateKey: Uint8Array) => {
    if (privateKey.length !== PRIVATE_KEY_LENGTH) {
        throw new Error(
            `Invalid secp256k1 private key: expected ${PRIVATE_KEY_LENGTH} bytes`
        )
    }
}

export const createKeyPair = () => {
    const privateKey = secp256k1.utils.randomSecretKey()
    const publicKey = secp256k1.getPublicKey(privateKey, false)
    return {
        privateKey,
        publicKey: toCantonPublicKey(publicKey),
    }
}

export const validatePublicKey = (publicKey: Uint8Array) => {
    parseCantonPublicKey(publicKey)
}

export const sign = (message: Uint8Array, privateKey: Uint8Array) => {
    validatePrivateKey(privateKey)
    // Canton supplies the already-computed transaction/topology hash as the
    // message. EC_DSA_SHA_256 applies SHA-256 to those bytes before ECDSA.
    return secp256k1.sign(sha256(message), privateKey).toDERRawBytes()
}

export const verify = (
    message: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array
) =>
    secp256k1.verify(
        signature,
        sha256(message),
        parseCantonPublicKey(publicKey)
    )

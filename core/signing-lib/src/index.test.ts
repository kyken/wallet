// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest'
import { verify as verifyWithNodeCrypto } from 'node:crypto'
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import {
    createKeyPair,
    getPublicKeyFromPrivate,
    signMessage,
    signTransactionHash,
    signTransactionHashWithAlgorithm,
    validatePublicKey,
    verifySignedTxHash,
} from './index'

const TX_HASH =
    '88beb0783e394f6128699bad42906374ab64197d260db05bb0cfeeb518ba3ac2'

describe('getPublicKeyFromPrivate', () => {
    it('derives the matching public key', () => {
        const { publicKey, privateKey } = createKeyPair()

        expect(getPublicKeyFromPrivate(privateKey)).toBe(publicKey)
    })

    it('derives a Canton-compatible secp256k1 public key', () => {
        const { publicKey, privateKey } = createKeyPair('secp256k1')

        expect(getPublicKeyFromPrivate(privateKey, 'secp256k1')).toBe(publicKey)
    })
})

describe('signTransactionHash', () => {
    it('produces a signature that verifySignedTxHash accepts', () => {
        const { publicKey, privateKey } = createKeyPair()
        const signature = signTransactionHash(TX_HASH, privateKey)

        expect(verifySignedTxHash(TX_HASH, publicKey, signature)).toBe(true)
    })

    it('is rejected by verifySignedTxHash with a different public key', () => {
        const { privateKey } = createKeyPair()
        const { publicKey: otherPublicKey } = createKeyPair()
        const signature = signTransactionHash(TX_HASH, privateKey)

        expect(verifySignedTxHash(TX_HASH, otherPublicKey, signature)).toBe(
            false
        )
    })

    it('supports Canton secp256k1 signing with DER signatures', () => {
        const { publicKey, privateKey } = createKeyPair('secp256k1')
        const publicKeyBytes = naclUtil.decodeBase64(publicKey)
        const privateKeyBytes = naclUtil.decodeBase64(privateKey)
        const signature = signTransactionHashWithAlgorithm(
            TX_HASH,
            privateKey,
            'secp256k1'
        )
        const signatureBytes = naclUtil.decodeBase64(signature)

        expect(publicKeyBytes).toHaveLength(88)
        expect(privateKeyBytes).toHaveLength(32)
        expect(signatureBytes[0]).toBe(0x30)

        expect(
            verifyWithNodeCrypto(
                'sha256',
                Buffer.from(naclUtil.decodeBase64(TX_HASH)),
                {
                    key: Buffer.from(publicKeyBytes),
                    format: 'der',
                    type: 'spki',
                },
                Buffer.from(signatureBytes)
            )
        ).toBe(true)

        expect(
            verifySignedTxHash(TX_HASH, publicKey, signature, 'secp256k1')
        ).toBe(true)
    })

    it('rejects a secp256k1 key when the legacy Ed25519 helper is used', () => {
        const { privateKey } = createKeyPair('secp256k1')

        expect(() => signTransactionHash(TX_HASH, privateKey)).toThrow(
            /Ed25519 private key/
        )
    })

    it('reports a clear error for an Ed25519 key under the secp256k1 profile', () => {
        const { privateKey } = createKeyPair()

        expect(() =>
            signTransactionHashWithAlgorithm(TX_HASH, privateKey, 'secp256k1')
        ).toThrow(/secp256k1 private key/)
    })
})

describe('signMessage', () => {
    it('signs a UTF-8 message with the private key', () => {
        const message = 'message'
        const { publicKey, privateKey } = createKeyPair()
        const signature = signMessage(message, privateKey)

        expect(
            nacl.sign.detached.verify(
                new TextEncoder().encode(message),
                naclUtil.decodeBase64(signature),
                naclUtil.decodeBase64(publicKey)
            )
        ).toBe(true)
    })
})

describe('verifySignedTxHash', () => {
    it('rejects an invalid signature', () => {
        const { publicKey } = createKeyPair()
        const invalidSignature = naclUtil.encodeBase64(
            Uint8Array.from({ length: nacl.sign.signatureLength }, () => 0)
        )

        expect(verifySignedTxHash(TX_HASH, publicKey, invalidSignature)).toBe(
            false
        )
    })
})

describe('validatePublicKey', () => {
    it('accepts Canton Ed25519 and secp256k1 public keys', () => {
        const ed25519PublicKey = 'PJCUPZmCN134OST9ofcs2BGLJ/4ju8BT/xiZjzSO6t4='
        const secp256k1PublicKey = createKeyPair('secp256k1').publicKey

        expect(() => validatePublicKey(ed25519PublicKey)).not.toThrow()
        expect(() =>
            validatePublicKey(secp256k1PublicKey, 'secp256k1')
        ).not.toThrow()
    })

    it('rejects a public key that does not match the selected algorithm', () => {
        const ed25519PublicKey = 'PJCUPZmCN134OST9ofcs2BGLJ/4ju8BT/xiZjzSO6t4='

        expect(() => validatePublicKey(ed25519PublicKey, 'secp256k1')).toThrow(
            /Canton DER X.509 SubjectPublicKeyInfo/
        )
    })
})

// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { AuthContext } from '@canton-network/core-wallet-auth'
import { Methods } from './rpc-gen/index.js'
import { Error as RpcError } from './rpc-gen/typings.js'
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'
import { SigningProvider } from './config/schema.js'
import { SigningAlgorithm, getCantonSigningProfile } from './canton.js'
import * as secp256k1Signing from './secp256k1.js'

export * from './canton.js'

// Re-export SigningProvider from config schema
export { SigningProvider }

export { default as buildController, type Methods } from './rpc-gen/index.js'
export * from './rpc-gen/typings.js'
export * from './SigningDriverStore.js'
export * from './config/schema.js'

export const CC_COIN_TYPE = 6767

export function isRpcError<T>(value: T | RpcError): value is RpcError {
    return (value as RpcError).error_description !== undefined
}

export enum PartyMode {
    INTERNAL = 'internal',
    EXTERNAL = 'external',
}

export type PublicKey = string
export type PrivateKey = string

export interface KeyPair {
    publicKey: PublicKey
    privateKey: PrivateKey
}

export interface SigningDriverInterface {
    partyMode: PartyMode
    signingProvider: SigningProvider
    controller: (userId: AuthContext['userId'] | undefined) => Methods
}

export const verifySignedTxHash = (
    txHash: string,
    publicKey: string,
    signature: string,
    signingAlgorithm: SigningAlgorithm = 'ed25519'
): boolean => {
    if (signingAlgorithm === 'secp256k1') {
        return secp256k1Signing.verify(
            naclUtil.decodeBase64(txHash),
            naclUtil.decodeBase64(publicKey),
            naclUtil.decodeBase64(signature)
        )
    }

    getCantonSigningProfile(signingAlgorithm)
    return nacl.sign.detached.verify(
        naclUtil.decodeBase64(txHash),
        naclUtil.decodeBase64(signature),
        naclUtil.decodeBase64(publicKey)
    )
}

export const validatePublicKey = (
    publicKeyBase64: string,
    signingAlgorithm: SigningAlgorithm = 'ed25519'
) => {
    let publicKey: Uint8Array
    try {
        publicKey = naclUtil.decodeBase64(publicKeyBase64)
    } catch {
        throw new Error(
            `Invalid ${signingAlgorithm} public key: expected base64-encoded Canton key material`
        )
    }

    if (signingAlgorithm === 'secp256k1') {
        secp256k1Signing.validatePublicKey(publicKey)
        return
    }

    getCantonSigningProfile(signingAlgorithm)
    if (publicKey.length !== nacl.sign.publicKeyLength) {
        throw new Error(
            `Invalid Ed25519 public key: expected ${nacl.sign.publicKeyLength} bytes. Check the SDK signingAlgorithm configuration.`
        )
    }
}

const decodePrivateKey = (
    privateKey: string,
    signingAlgorithm: SigningAlgorithm
) => {
    try {
        return naclUtil.decodeBase64(privateKey)
    } catch {
        throw new Error(
            `Invalid ${signingAlgorithm} private key: expected base64-encoded Canton key material`
        )
    }
}

const decodeEd25519PrivateKey = (privateKey: string) => {
    const decodedKey = decodePrivateKey(privateKey, 'ed25519')
    if (decodedKey.length !== nacl.sign.secretKeyLength) {
        throw new Error(
            `Invalid Ed25519 private key: expected ${nacl.sign.secretKeyLength} bytes. Check the SDK signingAlgorithm configuration.`
        )
    }

    return decodedKey
}

export const signTransactionHash = (
    txHash: string,
    privateKey: string
): string => {
    const decodedKey = decodeEd25519PrivateKey(privateKey)
    const decodedHash = naclUtil.decodeBase64(txHash)

    return naclUtil.encodeBase64(nacl.sign.detached(decodedHash, decodedKey))
}

/** @internal
 * Signs a Canton hash using an explicitly selected low-level profile.
 * SDK consumers should use `sdk.keys.signTransactionHash`, which takes its
 * profile from the SDK instance configuration.
 */
export const signTransactionHashWithAlgorithm = (
    txHash: string,
    privateKey: string,
    signingAlgorithm: SigningAlgorithm
): string => {
    if (signingAlgorithm === 'ed25519') {
        return signTransactionHash(txHash, privateKey)
    }

    getCantonSigningProfile(signingAlgorithm)
    return naclUtil.encodeBase64(
        secp256k1Signing.sign(
            naclUtil.decodeBase64(txHash),
            decodePrivateKey(privateKey, 'secp256k1')
        )
    )
}

export const signMessage = (message: string, privateKey: string): string => {
    const msgBytes = new TextEncoder().encode(message)
    const decodedKey = naclUtil.decodeBase64(privateKey)
    return naclUtil.encodeBase64(nacl.sign.detached(msgBytes, decodedKey))
}

export const getPublicKeyFromPrivate = (privateKeyBase64: string): string => {
    const secretKey = decodeEd25519PrivateKey(privateKeyBase64)
    const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey)
    return naclUtil.encodeBase64(keyPair.publicKey)
}

export const createKeyPair = (
    signingAlgorithm: SigningAlgorithm = 'ed25519'
): KeyPair => {
    if (signingAlgorithm === 'secp256k1') {
        const keyPair = secp256k1Signing.createKeyPair()
        return {
            publicKey: naclUtil.encodeBase64(keyPair.publicKey),
            privateKey: naclUtil.encodeBase64(keyPair.privateKey),
        }
    }

    getCantonSigningProfile(signingAlgorithm)
    const key = nacl.sign.keyPair()
    const publicKey = naclUtil.encodeBase64(key.publicKey)
    const privateKey = naclUtil.encodeBase64(key.secretKey)

    return { publicKey, privateKey }
}

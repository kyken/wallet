// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { KeysNamespace } from './index.js'
import {
    signTransactionHash,
    verifySignedTxHash,
} from '@canton-network/core-signing-lib'
import { base64ToBytes } from '../utils/encoding.js'

describe('Keys namespace', () => {
    it('should generate a valid keypair to sign transactions with', () => {
        const keys = new KeysNamespace()
        const keyPair = keys.generate()

        const messageToSign = 'EiAbC9+Qc4sRfwZLpRB7+ZtCgLHYiIhiENMoM6DsFhcFHQ=='

        const signature = signTransactionHash(messageToSign, keyPair.privateKey)
        const verify = verifySignedTxHash(
            messageToSign,
            keyPair.publicKey,
            signature
        )

        expect(verify).toBe(true)
    })

    it('should generate and sign with the configured secp256k1 profile', () => {
        const keys = new KeysNamespace('secp256k1')
        const keyPair = keys.generate()

        const signature = keys.signTransactionHash(
            'iL6weD45T2E=',
            keyPair.privateKey
        )

        expect(base64ToBytes(signature)[0]).toBe(0x30)
        expect(
            verifySignedTxHash(
                'iL6weD45T2E=',
                keyPair.publicKey,
                signature,
                'secp256k1'
            )
        ).toBe(true)
    })

    it('should calculate the fingerprint correctly from a known base64 encoded public key', async () => {
        const keys = new KeysNamespace()
        const publicKeyWithKnownFingerprint =
            'PJCUPZmCN134OST9ofcs2BGLJ/4ju8BT/xiZjzSO6t4='

        const fingerprint = await keys.fingerprint(
            publicKeyWithKnownFingerprint
        )

        expect(fingerprint).toEqual(
            '1220def9be3ebfa2ff62e63e4ce8e05551f0487371447ac19178cfdb40da37b28059'
        )
    })
})

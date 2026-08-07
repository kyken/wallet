// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as mock from '../../__test__/mocks'
import {
    InitializedSDK,
    OfflineInitializedSDK,
    ExtendedInitializedSDK,
} from '../..'
import { KeysNamespace } from '../../namespace/keys'
import { SDKUtilsNamespace } from '../../namespace/utils'
import { LedgerNamespace } from '../../namespace/ledger'
import { PartyNamespace } from '../../namespace/party'
import { UserNamespace } from '../../namespace/user'
import { AmuletNamespace } from '../../namespace/amulet'
import { AssetNamespace } from '../../namespace/asset'
import { EventsNamespace } from '../../namespace/events'
import { TokenNamespace } from '../../namespace/token'
import { verifySignedTxHash } from '@canton-network/core-signing-lib'
import { SDK } from '../../sdk.js'
import { base64ToBytes } from '../../namespace/utils/encoding.js'

const {
    ValidatorInternalClient,
    get,
    TokenStandardService,
    AmuletService,
    ScanProxyClient,
    ScanClient,
} = vi.hoisted(() => {
    const get = vi.fn().mockImplementation(() =>
        Promise.resolve({
            party_id: 'partyId',
        })
    )

    const registriesToAssets = vi.fn().mockResolvedValue([])

    return {
        ValidatorInternalClient: vi.fn(
            class {
                get = get
            }
        ),
        get,
        TokenStandardService: vi.fn(
            class {
                registriesToAssets = registriesToAssets
            }
        ),
        AmuletService: vi.fn(class {}),
        ScanProxyClient: vi.fn(class {}),
        ScanClient: vi.fn(class {}),
    }
})

vi.mock('@canton-network/core-splice-client', async (importOriginal) => {
    const actual =
        await importOriginal<
            typeof import('@canton-network/core-splice-client')
        >()
    return {
        ...actual,
        ValidatorInternalClient,
        ScanProxyClient,
        ScanClient,
    }
})

vi.mock('@canton-network/core-token-standard-service', () => ({
    TokenStandardService,
}))

vi.mock('@canton-network/core-amulet-service', () => ({
    AmuletService,
}))

describe('init SDK', () => {
    describe('offline', () => {
        let sdk: OfflineInitializedSDK
        beforeEach(() => {
            vi.clearAllMocks()

            sdk = new OfflineInitializedSDK(mock.ctx)
        })

        it('should expose offline interface', () => {
            expect(sdk.keys).toBeInstanceOf(KeysNamespace)
            expect(sdk.utils).toBeInstanceOf(SDKUtilsNamespace)
        })

        it('should propagate the configured signing algorithm to key generation', () => {
            const configuredSdk = new OfflineInitializedSDK({
                ...mock.offlineCtx,
                signingAlgorithm: 'secp256k1',
            })
            const keyPair = configuredSdk.keys.generate()
            const signature = configuredSdk.keys.signTransactionHash(
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

        it('should accept the signing algorithm on SDK.createOffline', () => {
            const configuredSdk = SDK.createOffline({
                signingAlgorithm: 'secp256k1',
            })
            const keyPair = configuredSdk.keys.generate()

            expect(keyPair.privateKey).toHaveLength(44)
            expect(keyPair.publicKey).not.toHaveLength(44)
        })
    })

    describe('basic', () => {
        let sdk: InitializedSDK
        beforeEach(() => {
            vi.clearAllMocks()

            sdk = new InitializedSDK(mock.ctx)
        })

        it('should expose basic interface', () => {
            sdk = new InitializedSDK(mock.ctx)

            // OfflineSDKInterface
            expect(sdk.keys).toBeInstanceOf(KeysNamespace)
            expect(sdk.utils).toBeInstanceOf(SDKUtilsNamespace)

            // BasicSDKInterface
            expect(sdk.ledger).toBeInstanceOf(LedgerNamespace)
            expect(sdk.party).toBeInstanceOf(PartyNamespace)
            expect(sdk.user).toBeInstanceOf(UserNamespace)
            expect(sdk.registerPlugins).toBeDefined()
        })

        it('should propagate the signing algorithm through SDK.create', async () => {
            mock.ledgerProvider.request
                .mockResolvedValueOnce({ user: { id: 'test-user-id' } })
                .mockResolvedValueOnce({
                    connectedSynchronizers: [{ synchronizerId: 'sync-1' }],
                })

            const configuredSdk = await SDK.create({
                ledgerProvider: mock.ledgerProvider as never,
                signingAlgorithm: 'secp256k1',
            })
            const keyPair = configuredSdk.keys.generate()

            expect(keyPair.privateKey).toHaveLength(44)
            expect(keyPair.publicKey).not.toHaveLength(44)
        })
    })

    describe('extended', () => {
        beforeEach(async () => {
            vi.clearAllMocks()
        })

        it('should expose extended interface', async () => {
            const sdk = await ExtendedInitializedSDK.create(mock.ctx, {
                amulet: mock.amuletConfig,
                asset: mock.assetConfig,
                events: mock.eventsConfig,
                token: mock.tokenConfig,
            })

            // OfflineSDKInterface
            expect(sdk.keys).toBeInstanceOf(KeysNamespace)
            expect(sdk.utils).toBeInstanceOf(SDKUtilsNamespace)

            // BasicSDKInterface
            expect(sdk.ledger).toBeInstanceOf(LedgerNamespace)
            expect(sdk.party).toBeInstanceOf(PartyNamespace)
            expect(sdk.user).toBeInstanceOf(UserNamespace)
            expect(sdk.registerPlugins).toBeDefined()

            // ExtendedInitializedSDK
            expect(sdk.amulet).toBeInstanceOf(AmuletNamespace)
            expect(sdk.asset).toBeInstanceOf(AssetNamespace)
            expect(sdk.events).toBeInstanceOf(EventsNamespace)
            expect(sdk.token).toBeInstanceOf(TokenNamespace)
        })

        it('should create amulet namespace based on services', async () => {
            await ExtendedInitializedSDK.create(mock.ctx, {
                amulet: mock.amuletConfig,
            })

            expect(ScanClient).toHaveBeenCalledOnce()
            expect(ScanProxyClient).toHaveBeenCalledOnce()
            expect(TokenStandardService).toHaveBeenCalledOnce()
            expect(AmuletService).toHaveBeenCalledOnce()
        })

        it('should create token namespace based on services', async () => {
            await ExtendedInitializedSDK.create(mock.ctx, {
                token: mock.tokenConfig,
            })

            expect(get).toHaveBeenCalledOnce()
            expect(TokenStandardService).toHaveBeenCalledOnce()
        })

        it('should create asset namespace based on services', async () => {
            await ExtendedInitializedSDK.create(mock.ctx, {
                asset: mock.assetConfig,
            })

            expect(TokenStandardService).toHaveBeenCalledOnce()
        })
    })
})

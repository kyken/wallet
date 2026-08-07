// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, vi } from 'vitest'
import * as mock from '../../__test__/mocks'
import { LedgerCommonSchemas } from '@canton-network/core-ledger-client-types'
import { SignedTransaction } from '../transactions/signed'
import { SDKContext } from '../../sdk'

const defaultSignedTransactionResponse = {
    preparedTransaction: 'txn',
    preparedTransactionHash: 'hash',
    hashingSchemeVersion: 'HASHING_SCHEME_VERSION_V2' as const,
}

const defaultSignature = 'signature'

const { ctx, ledgerProvider } = mock

class MockACSReader {
    raw = {
        read: vi.fn(),
    }
}

class MockSignedTransaction extends SignedTransaction {
    constructor(ctx: SDKContext) {
        super(
            ctx,
            Promise.resolve({
                response: defaultSignedTransactionResponse,
                signature: defaultSignature,
            })
        )
    }
    response = vi.fn().mockResolvedValue(defaultSignedTransactionResponse)
    signature = vi.fn().mockResolvedValue(defaultSignature)
    execute = vi.fn()
}

class MockPreparedTransaction {}
class MockDarNamespace {}
class MockInternalLedgerNamespace {
    prepare = vi.fn()
}

const v4 = vi.fn()

vi.doMock('uuid', () => ({
    v4,
}))

vi.doMock('@canton-network/core-acs-reader', () => ({
    ACSReader: MockACSReader,
}))

vi.doMock('../transactions/signed', () => ({
    SignedTransaction: MockSignedTransaction,
}))

vi.doMock('../transactions/prepared', () => ({
    PreparedTransaction: MockPreparedTransaction,
}))

vi.doMock('./dar', () => ({
    DarNamespace: MockDarNamespace,
}))

vi.doMock('./internal', () => ({
    InternalLedgerNamespace: MockInternalLedgerNamespace,
}))

const { LedgerNamespace } = await import('./namespace')
type LedgerNamespaceType = InstanceType<typeof LedgerNamespace>

describe('Ledger Namespace', () => {
    let ledger: LedgerNamespaceType

    beforeEach(() => {
        vi.clearAllMocks()

        v4.mockReturnValue('uuid')

        ledger = new LedgerNamespace(ctx)
    })

    it('should expose correct interface', () => {
        expect(ledger.dar).toBeInstanceOf(MockDarNamespace)
        expect(ledger.internal).toBeInstanceOf(MockInternalLedgerNamespace)
        expect(ledger.acsReader).toBeInstanceOf(MockACSReader)
    })

    it('should call for correct endpoint when retrieving the ledger end offset', async () => {
        ledgerProvider.request.mockResolvedValueOnce({
            offset: 150,
        })

        const result = await ledger.ledgerEnd()

        expect(ledgerProvider.request).toHaveBeenCalledExactlyOnceWith({
            method: 'ledgerApi',
            params: {
                resource: '/v2/state/ledger-end',
                requestMethod: 'get',
            },
        })
        expect(result).toBe(150)
    })

    it('should successfully create a prepared transaction instance', () => {
        const preparedTransaction = ledger.prepare({
            partyId: 'partyId',
            commands: [],
        })

        expect(preparedTransaction).toBeInstanceOf(MockPreparedTransaction)
    })

    it('should produce a signed transaction based on external offline signature', () => {
        const preparedSubmission: LedgerCommonSchemas['JsPrepareSubmissionResponse'] =
            defaultSignedTransactionResponse

        const result = ledger.fromSignature(
            preparedSubmission,
            defaultSignature
        )

        expect(result).toBeInstanceOf(SignedTransaction)
    })

    it('should execute interactive submission flow', async () => {
        const expectedResult: LedgerCommonSchemas['ExecuteSubmissionAndWaitResponse'] =
            { updateId: 'updateId', completionOffset: 90 }
        ledgerProvider.request.mockResolvedValueOnce(expectedResult)

        const signedTransaction = new MockSignedTransaction(ctx)

        const result = await ledger.execute(signedTransaction, {
            partyId: 'party::123',
        })

        const bodyRequest = {
            userId: ctx.userId,
            preparedTransaction:
                defaultSignedTransactionResponse.preparedTransaction,
            hashingSchemeVersion: 'HASHING_SCHEME_VERSION_V2',
            submissionId: 'uuid',
            deduplicationPeriod: {
                Empty: {},
            },
            partySignatures: {
                signatures: [
                    {
                        party: 'party::123',
                        signatures: [
                            {
                                signature: defaultSignature,
                                signedBy: '123',
                                format: 'SIGNATURE_FORMAT_CONCAT',
                                signingAlgorithmSpec:
                                    'SIGNING_ALGORITHM_SPEC_ED25519',
                            },
                        ],
                    },
                ],
            },
        }

        expect(ledgerProvider.request).toHaveBeenCalledExactlyOnceWith({
            method: 'ledgerApi',
            params: {
                resource: '/v2/interactive-submission/executeAndWait',
                body: bodyRequest,
                requestMethod: 'post',
            },
        })

        expect(result).toEqual(expectedResult)
    })

    it('should submit secp256k1 signatures with Canton DER metadata', async () => {
        ledger = new LedgerNamespace({
            ...ctx,
            signingAlgorithm: 'secp256k1',
        })
        ledgerProvider.request.mockResolvedValueOnce({
            updateId: 'updateId',
            completionOffset: 90,
        })

        await ledger.execute(new MockSignedTransaction(ctx), {
            partyId: 'party::123',
        })

        const request = ledgerProvider.request.mock.calls.at(-1)?.[0] as {
            params: {
                body: {
                    partySignatures: {
                        signatures: Array<{
                            signatures: Array<{
                                format: string
                                signingAlgorithmSpec: string
                            }>
                        }>
                    }
                }
            }
        }
        expect(
            request.params.body.partySignatures.signatures[0].signatures[0]
        ).toMatchObject({
            format: 'SIGNATURE_FORMAT_DER',
            signingAlgorithmSpec: 'SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256',
        })
    })

    it('should add the signing algorithm to Canton rejection errors', async () => {
        ledger = new LedgerNamespace({
            ...ctx,
            signingAlgorithm: 'secp256k1',
        })
        ledgerProvider.request.mockRejectedValueOnce(
            new Error('unsupported key specification')
        )

        await expect(
            ledger.execute(new MockSignedTransaction(ctx), {
                partyId: 'party::123',
            })
        ).rejects.toThrow(
            'Canton rejected secp256k1 signing request: unsupported key specification'
        )
    })
})

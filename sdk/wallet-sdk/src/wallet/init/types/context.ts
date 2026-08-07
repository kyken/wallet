// Copyright (c) 2025-2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { AbstractLedgerProvider } from '@canton-network/core-provider-ledger'
import { SDKLogger } from '../../logger/logger.js'
import { SDKErrorHandler } from '../../error/handler.js'
import type { SigningAlgorithm } from '@canton-network/core-signing-lib'

export type SDKContext = {
    ledgerProvider: AbstractLedgerProvider
    userId: string
    logger: SDKLogger
    error: SDKErrorHandler
    defaultSynchronizerId: string
    signingAlgorithm?: SigningAlgorithm
}

export type OfflineSDKContext = {
    logger: SDKLogger
    error: SDKErrorHandler
    signingAlgorithm?: SigningAlgorithm
}

export const resolveSigningAlgorithm = (
    signingAlgorithm?: SigningAlgorithm
): SigningAlgorithm => signingAlgorithm ?? 'ed25519'

export const createSigningSubmissionError = (
    error: unknown,
    signingAlgorithm: SigningAlgorithm
) => {
    const message =
        typeof error === 'string'
            ? error
            : error instanceof Error
              ? error.message
              : 'Unknown Canton signing error'

    if (signingAlgorithm === 'ed25519' && error instanceof Error) {
        return error
    }

    return new Error(
        `Canton rejected ${signingAlgorithm} signing request: ${message}`
    )
}

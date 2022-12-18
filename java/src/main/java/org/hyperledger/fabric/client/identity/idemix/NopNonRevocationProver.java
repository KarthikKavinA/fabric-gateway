/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * NopNonRevocationProver is a concrete NonRevocationProver for RevocationAlgorithm "ALG_NO_REVOCATION".
 */
class NopNonRevocationProver implements NonRevocationProver {
    private final byte[] empty = new byte[0];

    public byte[] getFSContribution(final BIG rh, final BIG rRh, final Idemix.CredentialRevocationInformation cri) {
        return empty;
    }

    public Idemix.NonRevocationProof getNonRevocationProof(final BIG challenge) {
        return Idemix.NonRevocationProof.newBuilder()
                .setRevocationAlg(RevocationAlgorithm.ALG_NO_REVOCATION.ordinal())
                .build();
    }
}

/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * NopNonRevocationVerifier is a concrete NonRevocationVerifier for RevocationAlgorithm "ALG_NO_REVOCATION".
 */
class NopNonRevocationVerifier implements NonRevocationVerifier {

    private final byte[] empty = new byte[0];

    public byte[] recomputeFSContribution(final Idemix.NonRevocationProof proof, final BIG challenge, final ECP2 epochPK, final BIG proofSRh) {
        return empty;
    }
}


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
 * A NonRevocationProver is a prover that can prove that an identity mixer credential is not revoked.
 * For every RevocationAlgorithm, there will be an instantiation of NonRevocationProver.
 */
interface NonRevocationVerifier {
    /**
     * This method provides a non-revocation verifier depending on the Revocation algorithm.
     *
     * @param algorithm Revocation mechanism to use
     * @return NonRevocationVerifier or null if not allowed
     */
    static NonRevocationVerifier getNonRevocationVerifier(RevocationAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Revocation algorithm cannot be null");
        }
        switch (algorithm) {
            case ALG_NO_REVOCATION:
                return new NopNonRevocationVerifier();
            default:
                // Revocation algorithm not supported
                throw new Error("Revocation algorithm " + algorithm.name() + " not supported");
        }
    }

    /**
     * recomputeFSContribution verifies a non-revocation proof by recomputing the Fiat-Shamir contribution.
     *
     * @param proof     Non revocation proof
     * @param challenge Challenge
     * @param epochPK   Epoch PK
     * @param proofSRh  Proof of revocation handle
     * @return The recomputed FSContribution
     */
    byte[] recomputeFSContribution(Idemix.NonRevocationProof proof, BIG challenge, ECP2 epochPK, BIG proofSRh);
}

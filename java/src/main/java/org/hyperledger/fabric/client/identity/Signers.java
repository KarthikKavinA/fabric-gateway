/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.client.identity.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.client.identity.idemix.IdemixPseudonym;

/**
 * Factory methods to create standard signing implementations.
 */
public final class Signers {

    /**
     * Create a new signer that uses the supplied private key for signing. The {@link Identities} class provides static
     * methods to create a {@code PrivateKey} object from PEM-format data.
     * @param privateKey A private key.
     * @return A signer implementation.
     */
    public static Signer newPrivateKeySigner(final PrivateKey privateKey) {
        if (privateKey instanceof ECPrivateKey) {
            return new ECPrivateKeySigner((ECPrivateKey) privateKey);
        } else {
            throw new IllegalArgumentException("Unsupported private key type: " + privateKey.getClass().getTypeName());
        }
    }

    /**
     * Create a new idemix signer that uses supplied Secret key for signing.
     * @param sk A Secret key.
     * @param pseudonym A Pseudonym
     * @param ipk A Public Key of an Issuer
     * @return A signer implementation.
     */
    public static Signer newIdemixPrivateKeySigner(final BIG sk, final IdemixPseudonym pseudonym, final IdemixIssuerPublicKey ipk) {

        if (sk == null || pseudonym == null || ipk == null) {
            throw new IllegalArgumentException("sk or pseudonym or ipk should not be null");
        }
        return new IdemixPrivateKeySigner(sk, pseudonym, ipk);

    }

    // Private constructor to prevent instantiation
    private Signers() { }
}

/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.RAND;

/**
 * IdemixIssuerKey represents an idemix issuer key pair.
 */
public class IdemixIssuerKey {

    private final BIG isk;
    private final IdemixIssuerPublicKey ipk;

    /**
     * Constructor.
     *
     * @param attributeNames the names of attributes as String array (must not contain duplicates)
     */
    IdemixIssuerKey(final String[] attributeNames) {
        final RAND rng = IdemixUtils.getRand();
        // generate the secret key
        isk = IdemixUtils.randModOrder(rng);

        // construct the corresponding public key
        ipk = new IdemixIssuerPublicKey(attributeNames, isk);
    }

    /**
     * @return The public part of the issuer key pair
     */
    IdemixIssuerPublicKey getIpk() {
        return ipk;
    }

    /**
     * @return The secret part of the issuer key pair
     */
    BIG getIsk() {
        return isk;
    }
}



/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.RAND;

/**
 * IdemixPseudonym is a class for generating a Fresh Pseudonym with sk and ipk.
 */
public class IdemixPseudonym {

    private final ECP nym;
    private final BIG randNym;

    /**
     * Constructor.
     *
     * @param sk  the secret key of the user
     * @param ipk the public key of the issuer
     */
    public IdemixPseudonym(final BIG sk, final IdemixIssuerPublicKey ipk) {
        if (sk == null || ipk == null) {
            throw new IllegalArgumentException("Cannot construct idemix pseudonym from null input");
        }
        final RAND rng = IdemixUtils.getRand();
        randNym = IdemixUtils.randModOrder(rng);
        nym = ipk.getHsk().mul2(sk, ipk.getHRand(), randNym);
    }

    /**
     * @return the value of the pseudonym as an ECP
     */
    public ECP getNym() {
        return nym;
    }

    /**
     * @return the secret randomness used to construct this pseudonym
     */
    BIG getRandNym() {
        return randNym;
    }
}

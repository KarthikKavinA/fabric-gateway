/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import java.security.GeneralSecurityException;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.client.identity.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.client.identity.idemix.IdemixPseudonym;
import org.hyperledger.fabric.client.identity.idemix.IdemixPseudonymSignature;

final class IdemixPrivateKeySigner implements Signer {
    private final BIG sk;
    private final IdemixPseudonym pseudonym;
    private final IdemixIssuerPublicKey ipk;

    IdemixPrivateKeySigner(final BIG sk, final IdemixPseudonym pseudonym, final IdemixIssuerPublicKey ipk) {
        this.sk = sk;
        this.pseudonym = pseudonym;
        this.ipk = ipk;
    }

    @Override
    public byte[] sign(final byte[] msg) throws GeneralSecurityException {
        if (msg == null) {
            throw new GeneralSecurityException("Message must not be null");
        }
        return new IdemixPseudonymSignature(this.sk, this.pseudonym, this.ipk, msg).toProto().toByteArray();
    }
}

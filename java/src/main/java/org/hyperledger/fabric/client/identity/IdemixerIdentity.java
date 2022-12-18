/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity;

import org.hyperledger.fabric.client.identity.idemix.IdemixIdentity;

/**
 * A client identity described by an Idemix Identity. The {@link Identities} class provides static methods to create
 * an Idemix Identity object.
 */
public final class IdemixerIdentity implements Identity {

    private final String mspId;
    private final IdemixIdentity idemixIdentity;
    private final byte[] credentials;

    /**
     * Constructor.
     * @param mspId A membership service provider identifier.
     * @param idemixIdentity An Idemix Identity.
     */
    public IdemixerIdentity(final String mspId, final IdemixIdentity idemixIdentity) {
        this.mspId = mspId;
        this.idemixIdentity = idemixIdentity;
        credentials = idemixIdentity.createIdentityByteArray();
    }

    @Override
    public String getMspId() {
        return mspId;
    }

    @Override
    public byte[] getCredentials() {
        return credentials.clone();
    }

    /**
     * Get a Idemix Identity for this identity.
     * @return An Idemix Identity.
     */
    public IdemixIdentity getIdemixIdentity() {
        return idemixIdentity;
    }

}

/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.hyperledger.fabric.protos.msp.Identities;

/**
 * Identity corresponds to the Identity in fabric MSP.
 * The Identity is attached to the transaction signature and
 * can be unique per user or unlinkable (depending on the implementation and requirements)
 * This is to be used at the peer side when verifying certificates/credentials that transactions are signed
 * with, and verifying signatures that correspond to these certificates.
 */
public interface Identity {

    /**
     * Converts an identity to bytes.
     *
     * @return SerializedIdentity
     */
    Identities.SerializedIdentity createSerializedIdentity();
}

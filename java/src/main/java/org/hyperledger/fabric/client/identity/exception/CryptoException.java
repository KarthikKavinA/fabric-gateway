/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.exception;

/**
 * CryptoException Class is a exception class for all crypto related exceptions.
 */
public class CryptoException extends BaseException {

    private static final long serialVersionUID = 1L;

    /**
     * This method accepts exception message as a string and an exception class.
     * @param message an exception message
     * @param parent a parent exception class
     */
    public CryptoException(final String message, final Exception parent) {
        super(message, parent);
    }

    /**
     * This method accepts exception message as a string.
     * @param message an exception message
     */
    public CryptoException(final String message) {
        super(message);
    }

}

/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.exception;

/**
 * InvalidArgumentException class is an exception class.
 */
public class InvalidArgumentException extends BaseException {
    private static final long serialVersionUID = -6094512275378074427L;

    /**
     * This method accepts exception message as a string and an exception class.
     * @param message an exception message
     * @param parent a parent exception class
     */
    public InvalidArgumentException(final String message, final Exception parent) {
        super(message, parent);
    }

    /**
     * This method accepts exception message as a string.
     * @param message an exception message
     */
    public InvalidArgumentException(final String message) {
        super(message);
    }

    /**
     * This method accepts throwable class.
     * @param t a throwable class object
     */
    public InvalidArgumentException(final Throwable t) {
        super(t);
    }
}


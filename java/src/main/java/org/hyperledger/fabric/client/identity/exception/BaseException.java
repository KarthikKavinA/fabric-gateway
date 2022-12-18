/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.exception;

/**
 * BaseException Class is a Base for all exceptions.
 */
public class BaseException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * This method accepts exception message as a string and an exception class.
     * @param message an exception message
     * @param parent a parent exception class
     */
    public BaseException(final String message, final Throwable parent) {
        super(message, parent);
    }

    /**
     * This method accepts exception message as a string.
     * @param message an exception message
     */
    public BaseException(final String message) {
        super(message);
    }

    /**
     * This method accepts throwable class.
     * @param t a throwable class object
     */
    public BaseException(final Throwable t) {
        super(t);
    }

}

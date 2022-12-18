/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.RAND;

/**
 * WeakBB contains the functions to use Weak Boneh-Boyen signatures (https://ia.cr/2004/171).
 */
public final class WeakBB {
    private WeakBB() {
        // private constructor for util class.
    }

    /**
     * WeakBB.KeyPair represents a key pair for weak Boneh-Boyen signatures.
     */
    public static final class KeyPair {
        private final BIG sk;
        private final ECP2 pk;

        private KeyPair() {
            final RAND rng = IdemixUtils.getRand();
            this.sk = IdemixUtils.randModOrder(rng);
            this.pk = IdemixUtils.GENG2.mul(sk);
        }

        /**
         * Get the Secret Key.
         * @return secret key
         */
        public BIG getSk() {
            return sk;
        }

        /**
         * Get the Public Key.
         * @return Public Key
         */
        public ECP2 getPk() {
            return pk;
        }
    }

    /**
     * Generate a new key-pair set.
     *
     * @return a freshly generated key pair
     */
    public static KeyPair weakBBKeyGen() {
        return new KeyPair();
    }

    /**
     * Produces a WBB signature for a give message.
     *
     * @param sk Secret key
     * @param m  Message
     * @return Signature
     */
    public static ECP weakBBSign(final BIG sk, final BIG m) {
        BIG exp = IdemixUtils.modAdd(sk, m, IdemixUtils.GROUP_ORDER);
        exp.invmodp(IdemixUtils.GROUP_ORDER);

        return IdemixUtils.GENG1.mul(exp);
    }

    /**
     * Verify a WBB signature for a certain message.
     *
     * @param pk  Public key
     * @param sig Signature
     * @param m   Message
     * @return True iff valid
     */
    public static boolean weakBBVerify(final ECP2 pk, final ECP sig, final BIG m) {
        ECP2 p = new ECP2();
        p.copy(pk);
        p.add(IdemixUtils.GENG2.mul(m));
        p.affine();

        return PAIR.fexp(PAIR.ate(p, sig)).equals(IdemixUtils.GENGT);
    }

}

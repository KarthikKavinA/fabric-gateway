/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.FP12;
import org.apache.milagro.amcl.FP256BN.FP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.FP256BN.ROM;
import org.apache.milagro.amcl.HASH256;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * IdemixUtils is a utility class for Idemix Operations.
 */
public final class IdemixUtils {

    private static final BIG GX = new BIG(ROM.CURVE_Gx);
    private static final BIG GY = new BIG(ROM.CURVE_Gy);
    static final ECP GENG1 = new ECP(GX, GY);
    private static final BIG PXA = new BIG(ROM.CURVE_Pxa);
    private static final BIG PXB = new BIG(ROM.CURVE_Pxb);
    private static final FP2 PX = new FP2(PXA, PXB);
    private static final BIG PYA = new BIG(ROM.CURVE_Pya);
    private static final BIG PYB = new BIG(ROM.CURVE_Pyb);
    private static final FP2 PY = new FP2(PYA, PYB);
    static final ECP2 GENG2 = new ECP2(PX, PY);
    static final FP12 GENGT = PAIR.fexp(PAIR.ate(GENG2, GENG1));
    static final BIG GROUP_ORDER = new BIG(ROM.CURVE_Order);
    static final int FIELD_BYTES = BIG.MODBYTES;
    static final int INT_FOUR = 4;

    private IdemixUtils() {
        // private constructor as there shouldn't be instances of this utility class
    }

    /**
     * Returns a random number generator, amcl.RAND,
     * initialized with a fresh seed.
     *
     * @return a random number generator
     */
    public static RAND getRand() {
        // construct a secure seed
        int seedLength = IdemixUtils.FIELD_BYTES;
        SecureRandom random = new SecureRandom();
        byte[] seed = random.generateSeed(seedLength);

        // create a new amcl.RAND and initialize it with the generated seed
        RAND rng = new RAND();
        rng.clean();
        rng.seed(seedLength, seed);

        return rng;
    }

    /**
     * Returns random Mod Order.
     * @param rng rng
     * @return a random BIG in 0, ..., GROUP_ORDER-1
     */
    public static BIG randModOrder(final RAND rng) {
        BIG q = new BIG(ROM.CURVE_Order);

        // Takes random element in this Zq.
        return BIG.randomnum(q, rng);
    }

    /**
     * hashModOrder hashes bytes to an amcl.BIG.
     * in 0, ..., GROUP_ORDER
     *
     * @param data the data to be hashed
     * @return a BIG in 0, ..., GROUP_ORDER-1 that is the hash of the data
     */
    public static BIG hashModOrder(final byte[] data) {
        HASH256 hash = new HASH256();
        for (byte b : data) {
            hash.process(b);
        }

        byte[] hasheddata = hash.hash();

        BIG ret = BIG.fromBytes(hasheddata);
        ret.mod(IdemixUtils.GROUP_ORDER);

        return ret;
    }

    /**
     * bigToBytes turns a BIG into a byte array.
     *
     * @param big the BIG to turn into bytes
     * @return a byte array representation of the BIG
     */
    public static byte[] bigToBytes(final BIG big) {
        byte[] ret = new byte[IdemixUtils.FIELD_BYTES];
        big.toBytes(ret);
        return ret;
    }

    /**
     * ecpToBytes turns an ECP into a byte array.
     *
     * @param e the ECP to turn into bytes
     * @return a byte array representation of the ECP
     */
    static byte[] ecpToBytes(final ECP e) {
        byte[] ret = new byte[2 * FIELD_BYTES + 1];
        e.toBytes(ret, false);
        return ret;
    }

    /**
     * ecpToBytes turns an ECP2 into a byte array.
     *
     * @param e the ECP2 to turn into bytes
     * @return a byte array representation of the ECP2
     */
    static byte[] ecpToBytes(final ECP2 e) {
        byte[] ret = new byte[INT_FOUR * FIELD_BYTES];
        e.toBytes(ret);
        return ret;
    }

    /**
     * append appends a byte array to an existing byte array.
     *
     * @param data     the data to which we want to append
     * @param toAppend the data to be appended
     * @return a new byte[] of data + toAppend
     */
    static byte[] append(final byte[] data, final byte[] toAppend) {

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            stream.write(data);
            stream.write(toAppend);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stream.toByteArray();
    }

    /**
     * append appends a boolean array to an existing byte array.
     * @param data     the data to which we want to append
     * @param toAppend the data to be appended
     * @return a new byte[] of data + toAppend
     */
    static byte[] append(final byte[] data, final boolean[] toAppend) {
        byte[] toAppendBytes = new byte[toAppend.length];
        for (int i = 0; i < toAppend.length; i++) {
            toAppendBytes[i] = toAppend[i] ? (byte) 1 : (byte) 0;
        }
        return append(data, toAppendBytes);
    }

    /**
     * Returns an amcl.BN256.ECP on input of an ECP protobuf object.
     *
     * @param w a protobuf object representing an ECP
     * @return a ECP created from the protobuf object
     */
    static ECP transformFromProto(final Idemix.ECP w) {
        byte[] valuex = w.getX().toByteArray();
        byte[] valuey = w.getY().toByteArray();
        return new ECP(BIG.fromBytes(valuex), BIG.fromBytes(valuey));
    }

    /**
     * Returns an amcl.BN256.ECP2 on input of an ECP2 protobuf object.
     *
     * @param w a protobuf object representing an ECP2
     * @return a ECP2 created from the protobuf object
     */
    static ECP2 transformFromProto(final Idemix.ECP2 w) {
        byte[] valuexa = w.getXa().toByteArray();
        byte[] valuexb = w.getXb().toByteArray();
        byte[] valueya = w.getYa().toByteArray();
        byte[] valueyb = w.getYb().toByteArray();
        FP2 valuex = new FP2(BIG.fromBytes(valuexa), BIG.fromBytes(valuexb));
        FP2 valuey = new FP2(BIG.fromBytes(valueya), BIG.fromBytes(valueyb));
        return new ECP2(valuex, valuey);
    }

    /**
     * Converts an amcl.BN256.ECP2 into an ECP2 protobuf object.
     *
     * @param w an ECP2 to be transformed into a protobuf object
     * @return a protobuf representation of the ECP2
     */
    static Idemix.ECP2 transformToProto(final ECP2 w) {

        byte[] valueXA = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueXB = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueYA = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueYB = new byte[IdemixUtils.FIELD_BYTES];

        w.getX().getA().toBytes(valueXA);
        w.getX().getB().toBytes(valueXB);
        w.getY().getA().toBytes(valueYA);
        w.getY().getB().toBytes(valueYB);

        return Idemix.ECP2.newBuilder()
                .setXa(ByteString.copyFrom(valueXA))
                .setXb(ByteString.copyFrom(valueXB))
                .setYa(ByteString.copyFrom(valueYA))
                .setYb(ByteString.copyFrom(valueYB))
                .build();
    }

    /**
     * Converts an amcl.BN256.ECP into an ECP protobuf object.
     *
     * @param w an ECP to be transformed into a protobuf object
     * @return a protobuf representation of the ECP
     */
    static Idemix.ECP transformToProto(final ECP w) {
        byte[] valueX = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueY = new byte[IdemixUtils.FIELD_BYTES];

        w.getX().toBytes(valueX);
        w.getY().toBytes(valueY);

        return Idemix.ECP.newBuilder().setX(ByteString.copyFrom(valueX)).setY(ByteString.copyFrom(valueY)).build();
    }

    /**
     * Takes input BIGs a, b, m and returns a+b modulo m.
     *
     * @param a the first BIG to add
     * @param b the second BIG to add
     * @param m the modulus
     * @return Returns a+b (mod m)
     */
    static BIG modAdd(final BIG a, final BIG b, final BIG m) {
        BIG c = a.plus(b);
        c.mod(m);
        return c;
    }

    /**
     * Modsub takes input BIGs a, b, m and returns a-b modulo m.
     *
     * @param a the minuend of the modular subtraction
     * @param b the subtrahend of the modular subtraction
     * @param m the modulus
     * @return returns a-b (mod m)
     */
    static BIG modSub(final BIG a, final BIG b, final BIG m) {
        return modAdd(a, BIG.modneg(b, m), m);
    }
}

/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * IdemixCredential represents a user's idemix credential,
 * which is a BBS+ signature (see "Constant-Size Dynamic k-TAA" by Man Ho Au, Willy Susilo, Yi Mu)
 * on the user's secret key and attribute values.
 */
public class IdemixCredential {

    private final ECP aa;
    private final ECP bb;
    private final BIG ee;
    private final BIG ss;
    private final byte[][] attributes;

    /**
     * Constructor creating a new credential.
     *
     * @param key   the issuer key pair
     * @param m     a credential request
     * @param attrs an array of attribute values as BIG
     */
    IdemixCredential(final IdemixIssuerKey key, final IdemixCredRequest m, final BIG[] attrs) {
        if (key == null || key.getIpk() == null || m == null || attrs == null) {
            throw new IllegalArgumentException("Cannot create idemix credential from null input");
        }
        if (attrs.length != key.getIpk().getAttributeNames().length) {
            throw new IllegalArgumentException("Amount of attribute values does not match amount of attributes in issuer public key");
        }
        final RAND rng = IdemixUtils.getRand();
        // Place a BBS+ signature on the user key and the attribute values
        // (For BBS+, see "Constant-Size Dynamic k-TAA" by Man Ho Au, Willy Susilo, Yi Mu)
        ee = IdemixUtils.randModOrder(rng);
        ss = IdemixUtils.randModOrder(rng);

        bb = new ECP();
        bb.copy(IdemixUtils.GENG1);
        bb.add(m.getNym());
        bb.add(key.getIpk().getHRand().mul(ss));

        for (int i = 0; i < attrs.length / 2; i++) {
            bb.add(key.getIpk().getHAttrs()[2 * i].mul2(attrs[2 * i], key.getIpk().getHAttrs()[2 * i + 1], attrs[2 * i + 1]));
        }
        if (attrs.length % 2 != 0) {
            bb.add(key.getIpk().getHAttrs()[attrs.length - 1].mul(attrs[attrs.length - 1]));
        }

        BIG exp = new BIG(key.getIsk()).plus(ee);
        exp.mod(IdemixUtils.GROUP_ORDER);
        exp.invmodp(IdemixUtils.GROUP_ORDER);
        aa = bb.mul(exp);

        attributes = new byte[attrs.length][IdemixUtils.FIELD_BYTES];
        byte[] b = new byte[IdemixUtils.FIELD_BYTES];
        for (int i = 0; i < attrs.length; i++) {
            attrs[i].toBytes(b);
            System.arraycopy(b, 0, attributes[i], 0, IdemixUtils.FIELD_BYTES);
        }
    }

    /**
     * Construct an IdemixCredential from a serialized credential.
     *
     * @param proto a protobuf representation of a credential
     */
    public IdemixCredential(final Idemix.Credential proto) {
        if (proto == null) {
            throw new IllegalArgumentException("Cannot create idemix credential from null input");
        }

        aa = IdemixUtils.transformFromProto(proto.getA());
        bb = IdemixUtils.transformFromProto(proto.getB());
        ee = BIG.fromBytes(proto.getE().toByteArray());
        ss = BIG.fromBytes(proto.getS().toByteArray());
        attributes = new byte[proto.getAttrsCount()][];
        for (int i = 0; i < proto.getAttrsCount(); i++) {
            attributes[i] = proto.getAttrs(i).toByteArray();
        }
    }

    /**
     * Get ECP aa.
     * @return ecp a
     */
    ECP getA() {
        return aa;
    }

    /**
     * Get ECP bb.
     * @return ecp b
     */
    ECP getB() {
        return bb;
    }

    /**
     * Get ECP ee.
     * @return ecp e
     */
    BIG getE() {
        return ee;
    }

    /**
     * Get ECP ss.
     * @return ecp s
     */
    BIG getS() {
        return ss;
    }

    /**
     * Get attributes.
     * @return byte array of array
     */
    public byte[][] getAttrs() {
        return attributes;
    }

    /**
     * verify cryptographically verifies the credential.
     *
     * @param sk  the secret key of the user
     * @param ipk the public key of the issuer
     * @return true iff valid
     */
    public boolean verify(final BIG sk, final IdemixIssuerPublicKey ipk) {
        if (ipk == null || attributes.length != ipk.getAttributeNames().length) {
            return false;
        }
        for (byte[] attr : attributes) {
            if (attr == null) {
                return false;
            }
        }

        ECP bPrime = new ECP();
        bPrime.copy(IdemixUtils.GENG1);
        bPrime.add(ipk.getHsk().mul2(sk, ipk.getHRand(), ss));
        for (int i = 0; i < attributes.length / 2; i++) {
            bPrime.add(ipk.getHAttrs()[2 * i].mul2(BIG.fromBytes(attributes[2 * i]), ipk.getHAttrs()[2 * i + 1], BIG.fromBytes(attributes[2 * i + 1])));
        }
        if (attributes.length % 2 != 0) {
            bPrime.add(ipk.getHAttrs()[attributes.length - 1].mul(BIG.fromBytes(attributes[attributes.length - 1])));
        }
        if (!bb.equals(bPrime)) {
            return false;
        }

        ECP2 a = IdemixUtils.GENG2.mul(ee);
        a.add(ipk.getW());
        a.affine();
        return PAIR.fexp(PAIR.ate(a, aa)).equals(PAIR.fexp(PAIR.ate(IdemixUtils.GENG2, bb)));
    }

    /**
     * @return A proto representation of this credential
     */
    Idemix.Credential toProto() {
        Idemix.Credential.Builder builder = Idemix.Credential.newBuilder()
                .setA(IdemixUtils.transformToProto(aa))
                .setB(IdemixUtils.transformToProto(bb))
                .setE(ByteString.copyFrom(IdemixUtils.bigToBytes(ee)))
                .setS(ByteString.copyFrom(IdemixUtils.bigToBytes(ss)));

        for (byte[] attr : attributes) {
            builder.addAttrs(ByteString.copyFrom(attr));
        }

        return builder.build();
    }
}

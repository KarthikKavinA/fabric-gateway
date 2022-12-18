/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * IdemixIssuerPublicKey is a class for representing the public key of the issuer.
 */
public class IdemixIssuerPublicKey {

    private final String[] attributeNames;
    private final ECP hsk;
    private final ECP hRand;
    private final ECP[] hAttrs;
    private final ECP2 w;
    private final ECP barG1;
    private final ECP barG2;
    private final BIG proofC;
    private final BIG proofS;
    private byte[] hash = new byte[0];

    /**
     * Constructor.
     *
     * @param attributeNamesArray the names of attributes as String array (must not contain duplicates)
     * @param isk            the issuer secret key
     */
    IdemixIssuerPublicKey(final String[] attributeNamesArray, final BIG isk) {
        // check null input
        if (attributeNamesArray == null || isk == null) {
            throw new IllegalArgumentException("Cannot create IdemixIssuerPublicKey from null input");
        }

        // Checking if attribute names are unique
        Set<String> map = new HashSet<>();
        for (String item : attributeNamesArray) {
            if (!map.add(item)) {
                throw new IllegalArgumentException("Attribute " + item + " appears multiple times in attributeNamesArray");
            }
        }
        final RAND rng = IdemixUtils.getRand();
        // Attaching Attribute Names array correctly
        attributeNames = attributeNamesArray;

        // Computing w value
        w = IdemixUtils.GENG2.mul(isk);

        // Filling up HAttributes correctly in Issuer Public Key, length
        // preserving
        hAttrs = new ECP[attributeNamesArray.length];

        for (int i = 0; i < attributeNamesArray.length; i++) {
            hAttrs[i] = IdemixUtils.GENG1.mul(IdemixUtils.randModOrder(rng));
        }

        // Generating hsk value
        hsk = IdemixUtils.GENG1.mul(IdemixUtils.randModOrder(rng));

        // Generating hRand value
        hRand = IdemixUtils.GENG1.mul(IdemixUtils.randModOrder(rng));

        // Generating barG1 value
        barG1 = IdemixUtils.GENG1.mul(IdemixUtils.randModOrder(rng));

        // Generating barG2 value
        barG2 = barG1.mul(isk);

        // Zero Knowledge Proofs

        // Computing t1 and t2 values with random local variable r for later use
        BIG r = IdemixUtils.randModOrder(rng);
        ECP2 t1 = IdemixUtils.GENG2.mul(r);
        ECP t2 = barG1.mul(r);

        // Generating proofData that will contain 3 elements in G1 (of size 2*FIELD_BYTES+1)and 3 elements in G2 (of size 4 * FIELD_BYTES)
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(IdemixUtils.GENG2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(barG1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(w));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(barG2));

        // Hashing proofData to proofC
        proofC = IdemixUtils.hashModOrder(proofData);

        // Computing proofS = (proofC*isk) + r mod GROUP_ORDER
        proofS = BIG.modmul(proofC, isk, IdemixUtils.GROUP_ORDER).plus(r);
        proofS.mod(IdemixUtils.GROUP_ORDER);

        // Compute hash of IdemixIssuerPublicKey
        byte[] serializedIpk = toProto().toByteArray();
        hash = IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(serializedIpk));
    }

    /**
     * Construct an IdemixIssuerPublicKey from a serialized issuer public key.
     * @param proto a protobuf representation of an issuer public key
     */
    public IdemixIssuerPublicKey(final Idemix.IssuerPublicKey proto) {
        // check for bad input
        if (proto == null) {
            throw new IllegalArgumentException("Cannot create IdemixIssuerPublicKey from null input");
        }
        if (proto.getHAttrsCount() < proto.getAttributeNamesCount()) {
            throw new IllegalArgumentException("Serialized IPk does not contain enough HAttr values");
        }

        attributeNames = new String[proto.getAttributeNamesCount()];
        for (int i = 0; i < proto.getAttributeNamesCount(); i++) {
            attributeNames[i] = proto.getAttributeNames(i);
        }

        hAttrs = new ECP[proto.getHAttrsCount()];
        for (int i = 0; i < proto.getHAttrsCount(); i++) {
            hAttrs[i] = IdemixUtils.transformFromProto(proto.getHAttrs(i));
        }

        barG1 = IdemixUtils.transformFromProto(proto.getBarG1());
        barG2 = IdemixUtils.transformFromProto(proto.getBarG2());
        hRand = IdemixUtils.transformFromProto(proto.getHRand());
        hsk = IdemixUtils.transformFromProto(proto.getHSk());
        proofC = BIG.fromBytes(proto.getProofC().toByteArray());
        proofS = BIG.fromBytes(proto.getProofS().toByteArray());
        w = IdemixUtils.transformFromProto(proto.getW());

        // Compute hash of IdemixIssuerPublicKey
        byte[] serializedIpk = toProto().toByteArray();
        hash = IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(serializedIpk));
    }

    /**
     * check whether the issuer public key is correct.
     * @return true iff valid
     */
    public boolean check() {
        // check formalities of IdemixIssuerPublicKey
        if (attributeNames == null || hsk == null || hRand == null || hAttrs == null
                || barG1 == null || barG1.is_infinity() || barG2 == null
                || hAttrs.length < attributeNames.length) {
            return false;
        }

        for (int i = 0; i < attributeNames.length; i++) {
            if (hAttrs[i] == null) {
                return false;
            }
        }

        // check proofs
        ECP2 t1 = IdemixUtils.GENG2.mul(proofS);
        ECP t2 = barG1.mul(proofS);

        t1.add(w.mul(BIG.modneg(proofC, IdemixUtils.GROUP_ORDER)));
        t2.add(barG2.mul(BIG.modneg(proofC, IdemixUtils.GROUP_ORDER)));

        // Generating proofData that will contain 3 elements in G1 (of size 2*FIELD_BYTES+1)and 3 elements in G2 (of size 4 * FIELD_BYTES)
        byte[] proofData = new byte[0];
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(t2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(IdemixUtils.GENG2));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(barG1));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(w));
        proofData = IdemixUtils.append(proofData, IdemixUtils.ecpToBytes(barG2));

        // Hash proofData to hproofdata and compare with proofC
        return Arrays.equals(IdemixUtils.bigToBytes(IdemixUtils.hashModOrder(proofData)), IdemixUtils.bigToBytes(proofC));
    }

    /**
     * @return A proto version of this issuer public key
     */
    public Idemix.IssuerPublicKey toProto() {

        Idemix.ECP[] ipkHAttrs = new Idemix.ECP[hAttrs.length];
        for (int i = 0; i < hAttrs.length; i++) {
            ipkHAttrs[i] = IdemixUtils.transformToProto(hAttrs[i]);
        }

        return Idemix.IssuerPublicKey.newBuilder()
                .setProofC(ByteString.copyFrom(IdemixUtils.bigToBytes(proofC)))
                .setProofS(ByteString.copyFrom(IdemixUtils.bigToBytes(proofS)))
                .setW(IdemixUtils.transformToProto(w))
                .setHSk(IdemixUtils.transformToProto(hsk))
                .setHRand(IdemixUtils.transformToProto(hRand))
                .addAllAttributeNames(Arrays.asList(attributeNames))
                .setHash(ByteString.copyFrom(hash))
                .setBarG1(IdemixUtils.transformToProto(barG1))
                .setBarG2(IdemixUtils.transformToProto(barG2))
                .addAllHAttrs(Arrays.asList(ipkHAttrs))
                .build();
    }

    /**
     * @return The names of the attributes certified with this issuer public key.
     */
    public String[] getAttributeNames() {
        return attributeNames;
    }

    /**
     * getHsk returns the hsk.
     * @return hsk
     */
    protected ECP getHsk() {
        return hsk;
    }

    /**
     * Get hRand.
     * @return hrand
     */
    protected ECP getHRand() {
        return hRand;
    }

    /**
     * Get H attributes.
     * @return hattributes
     */
    protected ECP[] getHAttrs() {
        return hAttrs;
    }

    /**
     * Get w.
     * @return w
     */
    protected ECP2 getW() {
        return w;
    }

    /**
     * @return A digest of this issuer public key
     */
    public byte[] getHash() {
        return hash;
    }
}

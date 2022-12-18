/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.hyperledger.fabric.client.identity.exception.CryptoException;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * RevocationAuthority is a class which will be used to revoke the identity.
 */
public final class RevocationAuthority {
    private RevocationAuthority() {
        // private constructor for utility class
    }

    /**
     * Depending on the selected revocation algorithm, the proof data length will be different.
     * This method will give the proof length for any supported revocation algorithm.
     *
     * @param alg The revocation algorithm
     * @return The proof data length for the given revocation algorithm
     */
    public static int getProofBytes(final RevocationAlgorithm alg) {
        if (alg == null) {
            throw new IllegalArgumentException("Revocation algorithm cannot be null");
        }
        switch (alg) {
            case ALG_NO_REVOCATION:
                return 0;
            default:
                throw new IllegalArgumentException("Unsupported RevocationAlgorithm: " + alg.name());
        }
    }

    /**
     * Generate a long term ECDSA key pair used for revocation.
     *
     * @return Freshly generated ECDSA key pair
     */
    public static java.security.KeyPair generateLongTermRevocationKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom random = new SecureRandom();
            AlgorithmParameterSpec params = new ECGenParameterSpec("secp384r1");
            keyGen.initialize(params, random);

            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error during the LTRevocation key. Invalid algorithm");
        }
    }

    /**
     * Creates a Credential Revocation Information object.
     *
     * @param key              Private key
     * @param unrevokedHandles Array of unrevoked revocation handles
     * @param epoch            The counter (representing a time window) in which this CRI is valid
     * @param alg              Revocation algorithm
     * @return CredentialRevocationInformation object
     */
    public static Idemix.CredentialRevocationInformation createCRI(final PrivateKey key, final BIG[] unrevokedHandles,
        final int epoch, final RevocationAlgorithm alg) throws CryptoException {
        Idemix.CredentialRevocationInformation.Builder builder = Idemix.CredentialRevocationInformation.newBuilder();
        builder.setRevocationAlg(alg.ordinal());
        builder.setEpoch(epoch);

        // Create epoch key
        WeakBB.KeyPair keyPair = WeakBB.weakBBKeyGen();
        if (alg == RevocationAlgorithm.ALG_NO_REVOCATION) {
            // Dummy PK in the proto
            builder.setEpochPk(IdemixUtils.transformToProto(IdemixUtils.GENG2));
        } else {
            // Real PK only if we are going to use it
            builder.setEpochPk(IdemixUtils.transformToProto(keyPair.getPk()));
        }

        // Sign epoch + epoch key with the long term key
        byte[] signed;
        try {
            Idemix.CredentialRevocationInformation cri = builder.build();
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(key);
            ecdsa.update(cri.toByteArray());
            signed = ecdsa.sign();

            builder.setEpochPkSig(ByteString.copyFrom(signed));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Error processing the signature");
        }

        if (alg == RevocationAlgorithm.ALG_NO_REVOCATION) {
            // build and return the credential information object
            return builder.build();
        } else {
            // If alg not supported, return null
            throw new IllegalArgumentException("Algorithm " + alg.name() + " not supported");
        }
    }

    /**
     * Verifies that the revocation PK for a certain epoch is valid,.
     * By checking that it was signed with the long term revocation key
     *
     * @param pk         Public Key
     * @param epochPK    Epoch PK
     * @param epochPkSig Epoch PK Signature
     * @param epoch      Epoch
     * @param alg        Revocation algorithm
     * @return True if valid
     */
    public static boolean verifyEpochPK(final PublicKey pk, final Idemix.ECP2 epochPK,
        final byte[] epochPkSig, final long epoch, final RevocationAlgorithm alg) throws CryptoException {
        Idemix.CredentialRevocationInformation.Builder builder = Idemix.CredentialRevocationInformation.newBuilder();
        builder.setRevocationAlg(alg.ordinal());
        builder.setEpochPk(epochPK);
        builder.setEpoch(epoch);
        Idemix.CredentialRevocationInformation cri = builder.build();
        byte[] bytesTosign = cri.toByteArray();
        try {
            Signature dsa = Signature.getInstance("SHA256withECDSA");
            dsa.initVerify(pk);
            dsa.update(bytesTosign);

            return dsa.verify(epochPkSig);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Error during the EpochPK verification", e);
        }
    }
}

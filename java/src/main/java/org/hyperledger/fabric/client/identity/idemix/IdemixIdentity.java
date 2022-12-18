/*
 * Copyright 2020 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import java.util.Arrays;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.hyperledger.fabric.client.identity.exception.CryptoException;
import org.hyperledger.fabric.client.identity.exception.InvalidArgumentException;
import org.hyperledger.fabric.protos.common.MspPrincipal;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.protos.msp.Identities;

/**
 * IdemixIdentity is a public serializable part of the IdemixSigningIdentity.
 * It contains an (un)linkable pseudonym, revealed attribute values, and a
 * corresponding proof of possession of an Idemix credential
 */
public class IdemixIdentity implements Identity {

    private static final Log LOGGER = LogFactory.getLog(IdemixIdentity.class);

    // MSP identifier
    private final String mspId;

    // Issuer public key hash
    private final byte[] ipkHash;

    // Idemix Pseudonym
    private final ECP pseudonym;

    // Organization Unit attribute
    private final String ou;

    // Role mask its a bitmask that represent all the roles attached to this identity
    private final int roleMask;

    // Proof of possession of Idemix credential
    // with respect to the pseudonym (nym)
    // and the corresponding attributes (ou, roleMask)
    private final IdemixSignature associationProof;

    /**
     * Create Idemix Identity from a Serialized Identity.
     *
     * @param proto a serialized identity protocol buffer
     */
    public IdemixIdentity(final Identities.SerializedIdentity proto) throws CryptoException, InvalidArgumentException {
        if (proto == null) {
            throw new InvalidArgumentException("Input must not be null");
        }

        this.mspId = proto.getMspid();

        try {
            LOGGER.trace("Fetching Idemix Proto");
            Identities.SerializedIdemixIdentity idemixProto = Identities.SerializedIdemixIdentity.parseFrom(proto.getIdBytes());

            if (idemixProto == null) {
                throw new IllegalArgumentException("The identity does not contain a serialized idemix identity");
            }
            LOGGER.trace("Deserializing Nym and attribute values");
            this.pseudonym = new ECP(BIG.fromBytes(idemixProto.getNymX().toByteArray()),
                    BIG.fromBytes(idemixProto.getNymY().toByteArray()));

            MspPrincipal.OrganizationUnit ou = MspPrincipal.OrganizationUnit.parseFrom(idemixProto.getOu());
            MspPrincipal.MSPRole role = MspPrincipal.MSPRole.parseFrom(idemixProto.getRole());

            this.ou = ou.getOrganizationalUnitIdentifier();
            this.roleMask = IdemixRoles.getRoleMask(role);
            this.ipkHash = ou.getCertifiersIdentifier().toByteArray();

            LOGGER.trace("Deserializing Proof");
            this.associationProof = new IdemixSignature(Idemix.Signature.parseFrom(idemixProto.getProof().toByteArray()));

        } catch (InvalidProtocolBufferException e) {
            throw new CryptoException("Cannot deserialize MSP ID", e);
        }
    }

    /**
     * Create Idemix Identity from the following inputs.
     *
     * @param mspId is MSP ID sting
     * @param ipk is a Issuer public key
     * @param nym   is Identity Mixer Pseudonym
     * @param ou    is OU attribute
     * @param roleMask  is a bitmask that represent all the roles attached to this identity
     * @param proof is Proof
     */
    public IdemixIdentity(final String mspId, final IdemixIssuerPublicKey ipk, final ECP nym, final String ou, final int roleMask, final IdemixSignature proof)
            throws InvalidArgumentException {

        if (mspId == null) {
            throw new InvalidArgumentException("MSP ID must not be null");
        }

        if (mspId.isEmpty()) {
            throw new InvalidArgumentException("MSP ID must not be empty");
        }

        if (ipk == null) {
            throw new InvalidArgumentException("Issuer Public Key must not be empty");
        }

        if (nym == null) {
            throw new InvalidArgumentException("Identity Mixer Pseudonym (nym) must not be null");
        }

        if (ou == null) {
            throw new InvalidArgumentException("OU attribute must not be null");
        }

        if (ou.isEmpty()) {
            throw new InvalidArgumentException("OU attribute must not be empty");
        }

        if (proof == null) {
            throw new InvalidArgumentException("Proof must not be null");
        }

        this.mspId = mspId;
        this.ipkHash = ipk.getHash();
        this.pseudonym = nym;
        this.ou = ou;
        this.roleMask = roleMask;
        this.associationProof = proof;
    }

    /**
     * Serialize Idemix Identity.
     */
    @Override
    public Identities.SerializedIdentity createSerializedIdentity() {
        MspPrincipal.OrganizationUnit ou = MspPrincipal.OrganizationUnit.newBuilder()
                .setCertifiersIdentifier(ByteString.copyFrom(this.ipkHash))
                .setMspIdentifier(this.mspId)
                .setOrganizationalUnitIdentifier(this.ou)
                .build();

        //Warning, this does not support multi-roleMask.
        //Serialize the bitmask is the correct way to support multi-roleMask in the future
        MspPrincipal.MSPRole role = MspPrincipal.MSPRole.newBuilder()
                .setRole(IdemixRoles.getMSPRoleFromIdemixRole(this.roleMask))
                .setMspIdentifier(this.mspId)
                .build();

        Identities.SerializedIdemixIdentity serializedIdemixIdentity = Identities.SerializedIdemixIdentity.newBuilder()
                .setProof(ByteString.copyFrom(this.associationProof.toProto().toByteArray()))
                .setOu(ByteString.copyFrom(ou.toByteArray()))
                .setRole(ByteString.copyFrom(role.toByteArray()))
                .setNymY(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getY())))
                .setNymX(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getX())))
                .build();

        return Identities.SerializedIdentity.newBuilder()
                .setIdBytes(ByteString.copyFrom(serializedIdemixIdentity.toByteArray()))
                .setMspid(this.mspId)
                .build();
    }

    /**
     * This method "createIdentityByteArray" returns identity byte array.
     * @return idemix identity byte array
     */
    public byte[] createIdentityByteArray() {
        MspPrincipal.OrganizationUnit ou = MspPrincipal.OrganizationUnit.newBuilder()
                .setCertifiersIdentifier(ByteString.copyFrom(this.ipkHash))
                .setMspIdentifier(this.mspId)
                .setOrganizationalUnitIdentifier(this.ou)
                .build();

        //Warning, this does not support multi-roleMask.
        //Serialize the bitmask is the correct way to support multi-roleMask in the future
        MspPrincipal.MSPRole role = MspPrincipal.MSPRole.newBuilder()
                .setRole(IdemixRoles.getMSPRoleFromIdemixRole(this.roleMask))
                .setMspIdentifier(this.mspId)
                .build();

        Identities.SerializedIdemixIdentity serializedIdemixIdentity = Identities.SerializedIdemixIdentity.newBuilder()
                .setProof(ByteString.copyFrom(this.associationProof.toProto().toByteArray()))
                .setOu(ByteString.copyFrom(ou.toByteArray()))
                .setRole(ByteString.copyFrom(role.toByteArray()))
                .setNymY(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getY())))
                .setNymX(ByteString.copyFrom(IdemixUtils.bigToBytes(this.pseudonym.getX())))
                .build();

        return serializedIdemixIdentity.toByteArray();
    }

    /**
     * This Method "getOuValue" returns OU as a string.
     * @return organizational Unit as a String
     */
    public String getOuValue() {
        return this.ou;
    }

    /**
     * This method getRoleMask will return roleMask Integer.
     * @return roleMask
     */
    public int getRoleMask() {
        return this.roleMask;
    }

    /**
     * toString Method will convert the objects to string.
     */
    @Override
    public String toString() {
        return "IdemixIdentity"
                + " [ MSP ID: " + this.mspId
                + " Issuer Public Key Hash: " + Arrays.toString(this.ipkHash)
                + " Pseudonym: " + this.pseudonym.toRawString()
                + " OU: " + this.ou
                + " Role mask: " + this.roleMask
                + " Association Proof: " + this.associationProof.toProto().toString()
                + " ]";
    }
}

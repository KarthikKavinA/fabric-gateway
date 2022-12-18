/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.client.identity.idemix;

import org.hyperledger.fabric.protos.common.MspPrincipal;

/**
 * IdemixRoles is ENUM type that represent a Idemix Role and provide some functionality to operate with Bitmasks.
 * And to operate between MSPRoles and IdemixRoles.
 */
public enum IdemixRoles {
    /**
     * Member.
     */
    MEMBER(1),
    /**
     * Admin.
     */
    ADMIN(2),
    /**
     * client.
     */
    CLIENT(4),
    /**
     * Peer.
     */
    PEER(8);
    // Next roles values: 8, 16, 32 ..

    private int value;

    IdemixRoles(final int value) {
        this.value = value;
    }

    int getValue() {
        return this.value;
    }

    /**
     * Receives an array of IdemixRoles and returns the bitmask combination of all.
     *
     * @param roles that we want to combine
     * @return bitmask
     */
    static int getRoleMask(final IdemixRoles[] roles) {
        int mask = 0;
        for (IdemixRoles role : roles) {
            mask = mask | role.value;
        }
        return mask;
    }

    /**
     * Receives an array of MspPrincipal.MSPRole and returns the bitmask combination of all.
     *
     * @param roles that we want to combine
     * @return bitmask
     */
    static int getRoleMask(final MspPrincipal.MSPRole[] roles) {
        int mask = 0;
        for (MspPrincipal.MSPRole role : roles) {
            mask = mask | getIdemixRoleFromMSPRole(role);
        }
        return mask;
    }

    /**
     * Receives a MspPrincipal.MSPRole and returns the bitmask.
     *
     * @param role that we want to combine
     * @return bitmask
     */
    static int getRoleMask(final MspPrincipal.MSPRole role) {
        return getRoleMask(new MspPrincipal.MSPRole[] {role});
    }

    /**
     * Receives a bitmask and a roleMask to test. If the roleMask is contained in the bit mask returns true.
     *
     * @param bitmask    where to test the roleMask
     * @param searchRole roleMask to test
     * @return true if roleMask contained
     */
    static boolean checkRole(final int bitmask, final IdemixRoles searchRole) {
        return (bitmask & searchRole.value) == searchRole.value;
    }

    /**
     * Receives a MSPRole and returns the correspondent IdemixRole value.
     *
     * @param role to transform to int
     * @return IdemixRole value
     */
    static int getIdemixRoleFromMSPRole(final MspPrincipal.MSPRole role) {
        return getIdemixRoleFromMSPRole(role.getRole());
    }

    /**
     * Receives a MSPRole Type and returns the correspondent IdemixRole value.
     *
     * @param type to transform to int
     * @return IdemixRole value
     */
    static int getIdemixRoleFromMSPRole(final MspPrincipal.MSPRole.MSPRoleType type) {
        return getIdemixRoleFromMSPRole(type.getNumber());
    }

    /**
     * Receives a MSPRole int value and returns the correspondent IdemixRole value.
     *
     * @param type to transform to int
     * @return IdemixRole value
     */
    static int getIdemixRoleFromMSPRole(final int type) {
        switch (type) {
            case MspPrincipal.MSPRole.MSPRoleType.ADMIN_VALUE:
                return ADMIN.getValue();
            case MspPrincipal.MSPRole.MSPRoleType.MEMBER_VALUE:
                return MEMBER.getValue();
            case MspPrincipal.MSPRole.MSPRoleType.PEER_VALUE:
                return PEER.getValue();
            case MspPrincipal.MSPRole.MSPRoleType.CLIENT_VALUE:
                return CLIENT.getValue();
            default:
                throw new IllegalArgumentException("The provided role is not valid: " + type);
        }
    }

    /**
     * Receives an integer that represents a roleMask and return the correspondent MSPRole value.
     *
     * @param role to transform to MSProle
     * @return MSPRole
     */
    static MspPrincipal.MSPRole.MSPRoleType getMSPRoleFromIdemixRole(final int role) {
        if (role == ADMIN.getValue()) {
            return MspPrincipal.MSPRole.MSPRoleType.ADMIN;
        }

        if (role == MEMBER.getValue()) {
            return MspPrincipal.MSPRole.MSPRoleType.MEMBER;
        }

        if (role == CLIENT.getValue()) {
            return MspPrincipal.MSPRole.MSPRoleType.CLIENT;
        }

        if (role == PEER.getValue()) {
            return MspPrincipal.MSPRole.MSPRoleType.PEER;
        }

        throw new IllegalArgumentException("The provided role value is not valid: " + role);
    }
}
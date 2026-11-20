/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.ntsd.utils;

import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.WellKnownSid;
import java.util.List;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;

/**
 * SDDL helper class.
 * Provides facilities to set and unset specific ACLs.
 */
public class SDDLHelper {

    /**
     * User cannot change password GUID.
     */
    public static final String UCP_OBJECT_GUID = AdExtendedRight.USER_CHANGE_PASSWORD.getGuidString();

    /**
     * Well-known SID string for Everyone (World).
     */
    public static final String EVERYONE_SID_STRING = WellKnownSid.EVERYONE.getSidString();

    /**
     * Well-known SID string for Principal Self.
     */
    public static final String SELF_SID_STRING = WellKnownSid.PRINCIPAL_SELF.getSidString();

    /**
     * Well-known SID string for Authenticated Users.
     */
    public static final String AUTHENTICATED_USERS_SID_STRING = WellKnownSid.AUTHENTICATED_USERS.getSidString();

    /**
     * Well-known SID string for Local System.
     */
    public static final String SYSTEM_SID_STRING = WellKnownSid.LOCAL_SYSTEM.getSidString();

    /**
     * Check if user cannot change password.
     * Evaluates the DACL in order so that compatible behavior across Windows Server 2008-2025 (including RSAT GUI
     * which may only re-add the Everyone allow ACE when unchecking) and Samba 4 is guaranteed.
     *
     * @param sddl SDDL.
     * @return <tt>true</tt> if user cannot change password; <tt>false</tt> otherwise.
     */
    public static boolean isUserCannotChangePassword(final SDDL sddl) {
        if (sddl == null || sddl.getDacl() == null) {
            return false;
        }

        Boolean everyoneAllowed = null;
        Boolean selfAllowed = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0, n = aces.size(); i < n; i++) {
            final ACE ace = aces.get(i);
            final AceType type = ace.getType();

            if ((type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    || type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                    && (ace.getRights() == null
                            || (ace.getRights().asUInt() & AceRights.ObjectRight.CR.getValue()) != 0)
                    && ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && AdExtendedRight.USER_CHANGE_PASSWORD.matches(ace.getObjectType())) {

                final SID sid = ace.getSid();
                // First matching ACE in DACL order wins for each trustee
                if (everyoneAllowed == null && isEveryoneSid(sid)) {
                    everyoneAllowed = (type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                } else if (selfAllowed == null && isSelfSid(sid)) {
                    selfAllowed = (type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                }
            }
        }

        // If either Everyone or Self is explicitly denied first in DACL evaluation order, user cannot change password
        return Boolean.FALSE.equals(everyoneAllowed) || Boolean.FALSE.equals(selfAllowed);
    }

    /**
     * Set "User Cannot Change Password ACL".
     *
     * @param sddl SDDL.
     * @param cannot <tt>true</tt> to set the ACL; <tt>false</tt> to unset.
     * @return updated SDDL.
     */
    public static SDDL userCannotChangePassword(final SDDL sddl, final Boolean cannot) {
        if (sddl == null || sddl.getDacl() == null) {
            return sddl;
        }

        final boolean deny = Boolean.TRUE.equals(cannot);
        final AceType type = deny ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

        // Remove all existing UCP ACEs for Everyone and Self (including duplicates left by external tools)
        ACE everyone = null;
        ACE self = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && AdExtendedRight.USER_CHANGE_PASSWORD.matches(ace.getObjectType())) {

                final SID sid = ace.getSid();
                if (isEveryoneSid(sid)) {
                    aces.remove(i--);
                    if (everyone == null) {
                        everyone = ace;
                    }
                } else if (isSelfSid(sid)) {
                    aces.remove(i--);
                    if (self == null) {
                        self = ace;
                    }
                }
            }
        }

        if (everyone != null) {
            everyone.setType(type);
        } else {
            everyone = createUcpAce(type, WellKnownSid.EVERYONE);
        }

        if (self != null) {
            self.setType(type);
        } else {
            self = createUcpAce(type, WellKnownSid.PRINCIPAL_SELF);
        }

        sddl.getDacl().addAceCanonical(everyone);
        sddl.getDacl().addAceCanonical(self);

        return sddl;
    }

    /**
     * Checks whether the given SID is Everyone (S-1-1-0) without allocating copies of byte arrays.
     *
     * @param sid SID to check.
     * @return true if S-1-1-0.
     */
    public static boolean isEveryoneSid(final SID sid) {
        return sid != null && sid.matchesSingleSubAuthority(0, 1, 0);
    }

    /**
     * Checks whether the given SID is Principal Self (S-1-5-10) without allocating copies of byte arrays.
     *
     * @param sid SID to check.
     * @return true if S-1-5-10.
     */
    public static boolean isSelfSid(final SID sid) {
        return sid != null && sid.matchesSingleSubAuthority(0, 5, 10);
    }

    private static ACE createUcpAce(final AceType type, final WellKnownSid wellKnownSid) {
        final ACE ace = ACE.newInstance(type);
        ace.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
        ace.setObjectType(AdExtendedRight.USER_CHANGE_PASSWORD);
        ace.setRights(new AceRights().addObjectRight(AceRights.ObjectRight.CR));
        ace.setSid(wellKnownSid.toSid());
        return ace;
    }
}

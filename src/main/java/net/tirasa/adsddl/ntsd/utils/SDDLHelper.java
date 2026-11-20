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

import java.util.Arrays;
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
    public static final String UCP_OBJECT_GUID = "ab721a53-1e2f-11d0-9819-00aa0040529b";

    /**
     * Well-known SID string for Everyone (World).
     */
    public static final String EVERYONE_SID_STRING = "S-1-1-0";

    /**
     * Well-known SID string for Principal Self.
     */
    public static final String SELF_SID_STRING = "S-1-5-10";

    /**
     * Well-known SID string for Authenticated Users.
     */
    public static final String AUTHENTICATED_USERS_SID_STRING = "S-1-5-11";

    /**
     * Well-known SID string for Local System.
     */
    public static final String SYSTEM_SID_STRING = "S-1-5-18";

    private static final byte[] UCP_OBJECT_GUID_BYTES = GUID.getGuidAsByteArray(UCP_OBJECT_GUID);

    private static final byte[] EVERYONE_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    private static final byte[] EVERYONE_SUB_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00 };

    private static final byte[] SELF_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

    private static final byte[] SELF_SUB_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x0a };

    /**
     * Check if user cannot change password.
     *
     * @param sddl SDDL.
     * @return <tt>true</tt> if user cannot change password; <tt>false</tt> otherwise.
     */
    public static boolean isUserCannotChangePassword(final SDDL sddl) {
        if (sddl == null || sddl.getDacl() == null) {
            return false;
        }

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0, n = aces.size(); i < n; i++) {
            final ACE ace = aces.get(i);

            if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && Arrays.equals(ace.getObjectType(), UCP_OBJECT_GUID_BYTES)) {

                final SID sid = ace.getSid();
                if (isEveryoneSid(sid) || isSelfSid(sid)) {
                    return true;
                }
            }
        }

        return false;
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

        ACE everyone = null;
        ACE self = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0, n = aces.size(); (everyone == null || self == null) && i < n; i++) {
            final ACE ace = aces.get(i);

            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && Arrays.equals(ace.getObjectType(), UCP_OBJECT_GUID_BYTES)) {

                final SID sid = ace.getSid();
                if (everyone == null && isEveryoneSid(sid)) {
                    everyone = ace;
                } else if (self == null && isSelfSid(sid)) {
                    self = ace;
                }
            }
        }

        if (everyone != null) {
            aces.remove(everyone);
            everyone.setType(type);
        } else {
            everyone = createUcpAce(type, EVERYONE_AUTHORITY, EVERYONE_SUB_AUTHORITY);
        }

        if (self != null) {
            aces.remove(self);
            self.setType(type);
        } else {
            self = createUcpAce(type, SELF_AUTHORITY, SELF_SUB_AUTHORITY);
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

    private static ACE createUcpAce(final AceType type, final byte[] authority, final byte[] subAuthority) {
        final ACE ace = ACE.newInstance(type);
        ace.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
        ace.setObjectType(UCP_OBJECT_GUID_BYTES);
        ace.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
        final SID sid = SID.newInstance(authority);
        sid.addSubAuthority(subAuthority);
        ace.setSid(sid);
        return ace;
    }
}

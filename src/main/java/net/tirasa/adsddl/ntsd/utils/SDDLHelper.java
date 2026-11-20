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
import net.tirasa.adsddl.ntsd.data.AceFlag;
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

        boolean res = false;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; !res && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && Arrays.equals(ace.getObjectType(), UCP_OBJECT_GUID_BYTES)) {

                final SID sid = ace.getSid();
                if (isEveryoneSid(sid) || isSelfSid(sid)) {
                    res = true;
                }
            }
        }

        return res;
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
        for (int i = 0; (everyone == null || self == null) && i < aces.size(); i++) {
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

        insertCanonical(aces, everyone);
        insertCanonical(aces, self);

        return sddl;
    }

    private static boolean isEveryoneSid(final SID sid) {
        return sid != null
                && sid.getSubAuthorityCount() == 1
                && Arrays.equals(sid.getIdentifierAuthority(), EVERYONE_AUTHORITY)
                && Arrays.equals(sid.getSubAuthorities().get(0), EVERYONE_SUB_AUTHORITY);
    }

    private static boolean isSelfSid(final SID sid) {
        return sid != null
                && sid.getSubAuthorityCount() == 1
                && Arrays.equals(sid.getIdentifierAuthority(), SELF_AUTHORITY)
                && Arrays.equals(sid.getSubAuthorities().get(0), SELF_SUB_AUTHORITY);
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

    private static void insertCanonical(final List<ACE> aces, final ACE aceToInsert) {
        final boolean isDeny = aceToInsert.getType() == AceType.ACCESS_DENIED_ACE_TYPE
                || aceToInsert.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE;

        int insertIndex = aces.size();
        for (int i = 0; i < aces.size(); i++) {
            final ACE current = aces.get(i);
            final boolean isInherited = current.getFlags().contains(AceFlag.INHERITED_ACE);
            if (isInherited) {
                insertIndex = i;
                break;
            }
            if (isDeny) {
                final boolean currentIsAllow = current.getType() == AceType.ACCESS_ALLOWED_ACE_TYPE
                        || current.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;
                if (currentIsAllow) {
                    insertIndex = i;
                    break;
                }
            }
        }
        aces.add(insertIndex, aceToInsert);
    }
}

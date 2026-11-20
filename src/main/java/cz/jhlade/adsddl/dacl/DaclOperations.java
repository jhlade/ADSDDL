package cz.jhlade.adsddl.dacl;

import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import cz.jhlade.adsddl.data.WellKnownSid;
import java.util.Arrays;
import java.util.List;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.SddlControlFlag;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;

/**
 * High-level Active Directory and Samba 4 DACL policy recipes and operations.
 * <p>
 * All mutation methods maintain Windows canonical DACL order ([MS-DTYP] section 2.4.5) and clean up duplicate
 * or conflicting explicit ACEs so that neither Windows RSAT (ADUC) nor Samba 4 {@code acl_modify} rejects or
 * warns about the resulting security descriptor.
 * </p>
 */
public final class DaclOperations {

    private static final long ACCIDENTAL_DELETION_MASK =
            (ObjectRight.SD.getValue() | ObjectRight.DT.getValue()) & 0xFFFFFFFFL;

    private DaclOperations() {
    }

    /**
     * Checks if "User cannot change password" is active on the given {@link SDDL}.
     *
     * @param sddl security descriptor.
     * @return true if user cannot change password.
     */
    public static boolean isUserCannotChangePassword(final SDDL sddl) {
        return SDDLHelper.isUserCannotChangePassword(sddl);
    }

    /**
     * Configures the "User cannot change password" policy on the given {@link SDDL}
     * (modifying the {@code User-Change-Password} extended right for {@code Everyone} and {@code Principal Self}).
     *
     * @param sddl security descriptor.
     * @param cannot true to deny password change, false to allow.
     * @return updated SDDL.
     */
    public static SDDL setUserCannotChangePassword(final SDDL sddl, final boolean cannot) {
        return SDDLHelper.userCannotChangePassword(sddl, cannot);
    }

    /**
     * Checks whether the AD object (typically an Organizational Unit or Container) is protected from accidental
     * deletion ("Protect object from accidental deletion" checkbox in ADUC).
     * <p>
     * In Active Directory and Samba 4, this is represented by an explicit {@code ACCESS_DENIED_ACE_TYPE} for
     * {@code Everyone (S-1-1-0)} denying {@code DELETE (SD)} and {@code ADS_RIGHT_DS_DELETE_TREE (DT)}.
     * </p>
     *
     * @param sddl security descriptor.
     * @return true if protected from accidental deletion.
     */
    public static boolean isProtectedFromAccidentalDeletion(final SDDL sddl) {
        if (sddl == null || sddl.getDacl() == null) {
            return false;
        }
        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0, n = aces.size(); i < n; i++) {
            final ACE ace = aces.get(i);
            if (ace.getType() == AceType.ACCESS_DENIED_ACE_TYPE
                    && !ace.getFlags().contains(AceFlag.INHERITED_ACE)
                    && !ace.getFlags().contains(AceFlag.INHERIT_ONLY_ACE)
                    && SDDLHelper.isEveryoneSid(ace.getSid())
                    && ace.getRights() != null
                    && (ace.getRights().asUInt() & ACCIDENTAL_DELETION_MASK) == ACCIDENTAL_DELETION_MASK) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sets or clears the "Protect object from accidental deletion" policy on an object's {@link SDDL}.
     *
     * @param sddl security descriptor.
     * @param protect true to deny {@code DELETE (SD)} and {@code DELETE_TREE (DT)} to {@code Everyone (S-1-1-0)},
     *                false to remove the protection ACE.
     * @return updated SDDL.
     */
    public static SDDL setProtectedFromAccidentalDeletion(final SDDL sddl, final boolean protect) {
        final ACL dacl = ensureDacl(sddl);
        if (dacl == null) {
            return sddl;
        }

        // Remove any existing accidental deletion deny ACEs for Everyone
        final List<ACE> aces = dacl.getAces();
        for (int i = 0; i < aces.size(); i++) {
            final ACE ace = aces.get(i);
            if (ace.getType() == AceType.ACCESS_DENIED_ACE_TYPE
                    && !ace.getFlags().contains(AceFlag.INHERITED_ACE)
                    && SDDLHelper.isEveryoneSid(ace.getSid())
                    && ace.getRights() != null
                    && (ace.getRights().asUInt() & ACCIDENTAL_DELETION_MASK) != 0) {
                final long remainingMask = ace.getRights().asUInt() & ~ACCIDENTAL_DELETION_MASK;
                if (remainingMask == 0) {
                    aces.remove(i--);
                } else {
                    ace.setRights(AceRights.parseValue((int) remainingMask));
                }
            }
        }

        if (protect) {
            final ACE denyDelete = AceBuilder.deny(WellKnownSid.EVERYONE)
                    .withRights(ObjectRight.SD, ObjectRight.DT)
                    .build();
            dacl.addAceCanonical(denyDelete);
        }

        return sddl;
    }

    /**
     * Checks whether the given manager {@link SID} is granted the right to update the {@code member} attribute
     * of a group ("Manager can update membership list" checkbox on the Managed By tab in ADUC).
     *
     * @param sddl group's security descriptor.
     * @param managerSid SID of the manager user or group.
     * @return true if the manager has explicit write property (WP) permission on {@code member}.
     */
    public static boolean canManagerUpdateMembershipList(final SDDL sddl, final SID managerSid) {
        if (sddl == null || sddl.getDacl() == null || managerSid == null) {
            return false;
        }
        return sddl.getDacl().findFirstAce(
                AceSelector.hasSid(managerSid)
                        .and(AceSelector.isAllow())
                        .and(AceSelector.hasRights(ObjectRight.WP))
                        .and(AceSelector.hasObjectType(AdSchemaGuid.ATTR_MEMBER))) != null;
    }

    /**
     * Grants or revokes the "Manager can update membership list" permission on a group's {@link SDDL}
     * (Write Property {@code WP} on {@link AdSchemaGuid#ATTR_MEMBER} for {@code managerSid}).
     *
     * @param sddl group's security descriptor.
     * @param managerSid SID of the manager user or group.
     * @param canUpdate true to grant {@code WP} on {@code member}, false to revoke it.
     * @return updated SDDL.
     */
    public static SDDL setManagerCanUpdateMembershipList(
            final SDDL sddl,
            final SID managerSid,
            final boolean canUpdate) {
        final ACL dacl = ensureDacl(sddl);
        if (dacl == null || managerSid == null) {
            return sddl;
        }

        dacl.removeAces(
                AceSelector.hasSid(managerSid)
                        .and(AceSelector.isExplicit())
                        .and(AceSelector.hasObjectType(AdSchemaGuid.ATTR_MEMBER)));

        if (canUpdate) {
            final ACE allowMemberWrite = AceBuilder.allow(managerSid)
                    .withRights(ObjectRight.WP)
                    .withObjectType(AdSchemaGuid.ATTR_MEMBER)
                    .build();
            dacl.addAceCanonical(allowMemberWrite);
        }

        return sddl;
    }

    /**
     * Checks whether the given principal {@link SID} has explicit {@code Send-As} permission on the object.
     *
     * @param sddl security descriptor.
     * @param principalSid trustee SID.
     * @return true if granted Send-As.
     */
    public static boolean hasSendAsPermission(final SDDL sddl, final SID principalSid) {
        if (sddl == null || sddl.getDacl() == null || principalSid == null) {
            return false;
        }
        return sddl.getDacl().findFirstAce(
                AceSelector.hasSid(principalSid)
                        .and(AceSelector.isAllow())
                        .and(AceSelector.hasExtendedRight(AdExtendedRight.SEND_AS))) != null;
    }

    /**
     * Grants or revokes the {@code Send-As} extended right for {@code principalSid} on a user, contact, or group.
     *
     * @param sddl security descriptor.
     * @param principalSid trustee SID.
     * @param allow true to grant Send-As, false to revoke explicit Send-As ACEs for this principal.
     * @return updated SDDL.
     */
    public static SDDL setSendAsPermission(
            final SDDL sddl,
            final SID principalSid,
            final boolean allow) {
        final ACL dacl = ensureDacl(sddl);
        if (dacl == null || principalSid == null) {
            return sddl;
        }

        dacl.removeAces(
                AceSelector.hasSid(principalSid)
                        .and(AceSelector.isExplicit())
                        .and(AceSelector.hasExtendedRight(AdExtendedRight.SEND_AS)));

        if (allow) {
            dacl.addAceCanonical(AceBuilder.allow(principalSid)
                    .withExtendedRight(AdExtendedRight.SEND_AS)
                    .build());
        }

        return sddl;
    }

    /**
     * Delegates User Password Reset & Force Password Change at Next Logon permissions to {@code delegateSid}
     * on an Organizational Unit (OU) for all descendant {@code user} objects:
     * <ul>
     *   <li>Extended right {@link AdExtendedRight#USER_FORCE_CHANGE_PASSWORD} ({@code CR}) on descendant users</li>
     *   <li>Read/Write property {@link AdSchemaGuid#ATTR_PWD_LAST_SET} ({@code RP, WP}) on descendant users</li>
     *   <li>Read/Write property {@link AdSchemaGuid#ATTR_LOCKOUT_TIME} ({@code RP, WP}) on descendant users</li>
     * </ul>
     *
     * @param ouSddl security descriptor of the Organizational Unit.
     * @param delegateSid SID of the delegated user or group (e.g. helpdesk / teachers / service account).
     * @return updated SDDL.
     */
    public static SDDL delegateUserPasswordResetOnOu(final SDDL ouSddl, final SID delegateSid) {
        final ACL dacl = ensureDacl(ouSddl);
        if (dacl == null || delegateSid == null) {
            return ouSddl;
        }

        // 1. User-Force-Change-Password on descendant user objects
        grantIdempotent(dacl, AceBuilder.allow(delegateSid)
                .withExtendedRight(AdExtendedRight.USER_FORCE_CHANGE_PASSWORD)
                .applyToDescendantsOnly(AdSchemaGuid.CLASS_USER)
                .build());

        // 2. Read/Write pwdLastSet on descendant user objects
        grantIdempotent(dacl, AceBuilder.allow(delegateSid)
                .withRights(ObjectRight.RP, ObjectRight.WP)
                .withObjectType(AdSchemaGuid.ATTR_PWD_LAST_SET)
                .applyToDescendantsOnly(AdSchemaGuid.CLASS_USER)
                .build());

        // 3. Read/Write lockoutTime on descendant user objects
        grantIdempotent(dacl, AceBuilder.allow(delegateSid)
                .withRights(ObjectRight.RP, ObjectRight.WP)
                .withObjectType(AdSchemaGuid.ATTR_LOCKOUT_TIME)
                .applyToDescendantsOnly(AdSchemaGuid.CLASS_USER)
                .build());

        return ouSddl;
    }

    /**
     * Configures whether the object's DACL is protected from inheriting permissions from parent containers
     * ({@link SddlControlFlag#SE_DACL_PROTECTED}).
     *
     * @param sddl security descriptor.
     * @param protectedDacl true to block DACL inheritance ({@code PD}), false to allow inheritance.
     * @param removeInheritedAces if {@code protectedDacl} is true and this is true, strips all existing
     *                            {@link AceFlag#INHERITED_ACE} entries from the DACL (equivalent to memilih
     *                            "Remove inherited permissions" in ADUC; false converts them to explicit ACEs).
     * @return updated SDDL.
     */
    public static SDDL setDaclInheritanceProtected(
            final SDDL sddl,
            final boolean protectedDacl,
            final boolean removeInheritedAces) {
        if (sddl == null) {
            return null;
        }
        if (protectedDacl) {
            sddl.addControlFlags(SddlControlFlag.SE_DACL_PROTECTED);
            if (sddl.getDacl() != null) {
                if (removeInheritedAces) {
                    sddl.getDacl().removeAces(AceSelector.isInherited());
                } else {
                    for (ACE ace : sddl.getDacl().getAces()) {
                        ace.removeFlag(AceFlag.INHERITED_ACE);
                    }
                    sddl.getDacl().sortCanonical();
                }
            }
        } else {
            sddl.removeControlFlags(SddlControlFlag.SE_DACL_PROTECTED);
        }
        return sddl;
    }

    /**
     * Grants an {@link ACE} on the target {@link ACL} idempotently: if an explicit ACE with the same type, flags,
     * trustee SID, ObjectType, and InheritedObjectType already exists, merges the rights bitmask into it;
     * otherwise inserts the new ACE in canonical order.
     *
     * @param acl target ACL.
     * @param newAce ACE to grant.
     * @return target ACL.
     */
    public static ACL grantIdempotent(final ACL acl, final ACE newAce) {
        if (acl == null || newAce == null) {
            return acl;
        }
        final List<ACE> aces = acl.getAces();
        for (int i = 0, n = aces.size(); i < n; i++) {
            final ACE existing = aces.get(i);
            if (existing.getType() == newAce.getType()
                    && existing.getSid() != null
                    && existing.getSid().equals(newAce.getSid())
                    && Arrays.equals(existing.getObjectType(), newAce.getObjectType())
                    && Arrays.equals(existing.getInheritedObjectType(), newAce.getInheritedObjectType())
                    && existing.getFlags().size() == newAce.getFlags().size()
                    && existing.getFlags().containsAll(newAce.getFlags())) {
                final long mergedMask = (existing.getRights() == null ? 0 : existing.getRights().asUInt())
                        | (newAce.getRights() == null ? 0 : newAce.getRights().asUInt());
                existing.setRights(AceRights.parseValue((int) mergedMask));
                return acl;
            }
        }
        acl.addAceCanonical(newAce);
        return acl;
    }

    private static ACL ensureDacl(final SDDL sddl) {
        if (sddl == null) {
            return null;
        }
        ACL dacl = sddl.getDacl();
        if (dacl == null) {
            dacl = new ACL();
            sddl.setDacl(dacl);
        }
        return dacl;
    }
}

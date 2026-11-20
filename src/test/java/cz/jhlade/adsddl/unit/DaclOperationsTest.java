package cz.jhlade.adsddl.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cz.jhlade.adsddl.dacl.AceBuilder;
import cz.jhlade.adsddl.dacl.AceSelector;
import cz.jhlade.adsddl.dacl.DaclOperations;
import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import cz.jhlade.adsddl.data.WellKnownSid;
import java.nio.file.Files;
import java.nio.file.Path;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.SddlControlFlag;
import org.junit.jupiter.api.Test;

public class DaclOperationsTest {

    @Test
    public void accidentalDeletionProtection() throws Exception {
        final byte[] src = Files.readAllBytes(Path.of(getClass().getResource("/daclOnlySample.bin").toURI()));
        final SDDL sddl = new SDDL(src);

        assertFalse(DaclOperations.isProtectedFromAccidentalDeletion(sddl));

        DaclOperations.setProtectedFromAccidentalDeletion(sddl, true);
        assertTrue(DaclOperations.isProtectedFromAccidentalDeletion(sddl));

        // Round-trip through binary wire format
        final SDDL parsed = new SDDL(sddl.toByteArray());
        assertTrue(DaclOperations.isProtectedFromAccidentalDeletion(parsed));

        // Verify the deny ACE was inserted at the beginning (before allow and inherited ACEs)
        final ACE firstAce = parsed.getDacl().getAce(0);
        assertTrue(WellKnownSid.EVERYONE.matches(firstAce.getSid()));
        assertTrue(AceSelector.isDeny().and(AceSelector.hasRights(ObjectRight.SD, ObjectRight.DT)).test(firstAce));

        // Unprotect
        DaclOperations.setProtectedFromAccidentalDeletion(parsed, false);
        assertFalse(DaclOperations.isProtectedFromAccidentalDeletion(parsed));
    }

    @Test
    public void groupManagerAndSendAsOperations() {
        final SDDL groupSddl = new SDDL();
        final SID teacherSid = SID.parse("S-1-5-21-1835709989-2027683138-697581538-2105");

        assertFalse(DaclOperations.canManagerUpdateMembershipList(groupSddl, teacherSid));
        DaclOperations.setManagerCanUpdateMembershipList(groupSddl, teacherSid, true);
        assertTrue(DaclOperations.canManagerUpdateMembershipList(groupSddl, teacherSid));

        assertFalse(DaclOperations.hasSendAsPermission(groupSddl, teacherSid));
        DaclOperations.setSendAsPermission(groupSddl, teacherSid, true);
        assertTrue(DaclOperations.hasSendAsPermission(groupSddl, teacherSid));

        final SDDL roundTrip = new SDDL(groupSddl.toByteArray());
        assertTrue(DaclOperations.canManagerUpdateMembershipList(roundTrip, teacherSid));
        assertTrue(DaclOperations.hasSendAsPermission(roundTrip, teacherSid));

        // Revoke manager membership update while keeping Send-As
        DaclOperations.setManagerCanUpdateMembershipList(roundTrip, teacherSid, false);
        assertFalse(DaclOperations.canManagerUpdateMembershipList(roundTrip, teacherSid));
        assertTrue(DaclOperations.hasSendAsPermission(roundTrip, teacherSid));
    }

    @Test
    public void delegatePasswordResetAndInheritanceProtection() {
        final SDDL ouSddl = new SDDL();
        final SID domainSid = SID.parse("S-1-5-21-1835709989-2027683138-697581538");
        final SID accountOperators = WellKnownSid.ACCOUNT_OPERATORS.toSid();
        final SID domainAdmins = WellKnownSid.DOMAIN_ADMINS.toSid(domainSid);

        assertEquals("S-1-5-32-548", accountOperators.toString());
        assertEquals("S-1-5-21-1835709989-2027683138-697581538-512", domainAdmins.toString());
        assertTrue(WellKnownSid.DOMAIN_ADMINS.matches(domainAdmins));

        // Add an inherited ACE and delegate password reset
        DaclOperations.delegateUserPasswordResetOnOu(ouSddl, accountOperators);
        ouSddl.getDacl().addAceCanonical(
                AceBuilder.allow(domainAdmins)
                        .withRights(ObjectRight.GA)
                        .withFlags(AceFlag.INHERITED_ACE, AceFlag.CONTAINER_INHERIT_ACE)
                        .build());

        // Calling delegateUserPasswordResetOnOu again is idempotent (still 3 delegated ACEs + 1 inherited ACE)
        DaclOperations.delegateUserPasswordResetOnOu(ouSddl, accountOperators);
        assertEquals(4, ouSddl.getDacl().getAceCount());

        final ACE resetAce = ouSddl.getDacl().findFirstAce(
                AceSelector.hasSid(accountOperators)
                        .and(AceSelector.hasExtendedRight(AdExtendedRight.USER_FORCE_CHANGE_PASSWORD))
                        .and(AceSelector.hasInheritedObjectType(AdSchemaGuid.CLASS_USER)));
        assertNotNull(resetAce);

        // Protect DACL and strip inherited ACEs
        DaclOperations.setDaclInheritanceProtected(ouSddl, true, true);
        assertTrue(ouSddl.hasControlFlag(SddlControlFlag.SE_DACL_PROTECTED));
        assertEquals(3, ouSddl.getDacl().getAceCount());
    }
}

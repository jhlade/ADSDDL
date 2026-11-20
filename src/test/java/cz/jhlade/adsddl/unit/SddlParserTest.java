/*
 * Copyright (C) 2026 Jan Hladěna (jan.hladena@gmail.com)
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
package cz.jhlade.adsddl.unit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cz.jhlade.adsddl.dacl.DaclOperations;
import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import cz.jhlade.adsddl.data.WellKnownSid;
import cz.jhlade.adsddl.sddl.SddlParser;
import java.nio.file.Files;
import java.nio.file.Path;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.SddlControlFlag;
import org.junit.jupiter.api.Test;

public class SddlParserTest {

    @Test
    public void roundTripBinarySamplesThroughSddlParser() throws Exception {
        final String[] samples = {
            "/sddlSample.bin",
            "/daclOnlySample.bin",
            "/sddlSampleForAssertor.bin",
            "/sddlSampleForAssertor2.bin"
        };

        for (String samplePath : samples) {
            final byte[] raw = Files.readAllBytes(Path.of(getClass().getResource(samplePath).toURI()));
            final SDDL original = new SDDL(raw);

            final String sddlStr = original.toString();
            final SDDL reparsed = SDDL.parse(sddlStr);

            assertEquals(original.getOwner(), reparsed.getOwner(), "Owner mismatch in " + samplePath);
            assertEquals(original.getGroup(), reparsed.getGroup(), "Group mismatch in " + samplePath);
            assertEquals(original.getDacl(), reparsed.getDacl(), "DACL mismatch in " + samplePath);
            assertEquals(original.getSacl(), reparsed.getSacl(), "SACL mismatch in " + samplePath);

            // Also verify round-trip when formatted with 2-letter WellKnownSid aliases (WD, PS, SY, BA...)
            // SddlParser automatically infers the domain SID from any S-1-5-21-... SID in the string!
            final String aliasedStr = original.toSddlString();
            final SDDL reparsedFromAliases = SDDL.parse(aliasedStr);
            assertEquals(original.getDacl(), reparsedFromAliases.getDacl(), "Aliased DACL mismatch in " + samplePath);
        }
    }

    @Test
    public void parseStandardMicrosoftSddlWithAliasesAndFlags() {
        final SID domainSid = SID.parse("S-1-5-21-1835709989-2027683138-697581538");
        final String msSddl = "O:DAG:DUD:PAI"
                + "(OD;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
                + "(OD;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)"
                + "(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;AO)"
                + "(A;CIID;GA;;;SY)"
                + "(A;CIID;0x001f01ff;;;BA)"
                + "S:PAR(AU;SAFA;SDWD;;;WD)";

        final SDDL sddl = SDDL.parse(msSddl, domainSid);

        assertEquals(WellKnownSid.DOMAIN_ADMINS.toSid(domainSid), sddl.getOwner());
        assertEquals(WellKnownSid.DOMAIN_USERS.toSid(domainSid), sddl.getGroup());
        assertTrue(sddl.hasControlFlag(SddlControlFlag.SE_DACL_PROTECTED));
        assertTrue(sddl.hasControlFlag(SddlControlFlag.SE_DACL_AUTO_INHERITED));
        assertTrue(sddl.hasControlFlag(SddlControlFlag.SE_SACL_PROTECTED));
        assertTrue(sddl.hasControlFlag(SddlControlFlag.SE_SACL_AUTO_INHERIT_REQ));

        assertTrue(DaclOperations.isUserCannotChangePassword(sddl));
        assertEquals(5, sddl.getDacl().getAceCount());
        assertEquals(1, sddl.getSacl().getAceCount());

        // Check delegated password reset ACE (index 2)
        final ACE resetAce = sddl.getDacl().getAce(2);
        assertEquals(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, resetAce.getType());
        assertTrue(resetAce.getFlags().contains(AceFlag.CONTAINER_INHERIT_ACE));
        assertTrue(resetAce.getFlags().contains(AceFlag.INHERIT_ONLY_ACE));
        assertTrue(AdExtendedRight.USER_FORCE_CHANGE_PASSWORD.matches(resetAce.getObjectType()));
        assertTrue(AdSchemaGuid.CLASS_USER.matches(resetAce.getInheritedObjectType()));
        assertEquals(WellKnownSid.ACCOUNT_OPERATORS.toSid(), resetAce.getSid());

        // Check SACL audit ACE
        final ACE auditAce = sddl.getSacl().getAce(0);
        assertEquals(AceType.SYSTEM_AUDIT_ACE_TYPE, auditAce.getType());
        assertTrue(auditAce.getFlags().contains(AceFlag.SUCCESSFUL_ACCESS_ACE_FLAG));
        assertTrue(auditAce.getFlags().contains(AceFlag.FAILED_ACCESS_ACE_FLAG));
        assertTrue(auditAce.getRights().getObjectRights().contains(ObjectRight.SD));
        assertTrue(auditAce.getRights().getObjectRights().contains(ObjectRight.WD));

        // Verify binary serialization and re-unmarshalling
        final byte[] bytes = sddl.toByteArray();
        final SDDL fromBytes = new SDDL(bytes);
        assertEquals(sddl.getOwner(), fromBytes.getOwner());
        assertEquals(sddl.getGroup(), fromBytes.getGroup());
        assertEquals(sddl.getDacl(), fromBytes.getDacl());
        assertEquals(sddl.getSacl(), fromBytes.getSacl());
        assertArrayEquals(bytes, fromBytes.toByteArray());
    }

    @Test
    public void parseDomainInferenceAndSingleAce() {
        // Domain SID inferred automatically from literal Owner SID S-1-5-21-...-500
        final String sddlWithLiteralOwner = "O:S-1-5-21-111-222-333-500G:DUD:(A;;RPWP;;;DA)";
        final SDDL parsed = SDDL.parse(sddlWithLiteralOwner);
        assertEquals("S-1-5-21-111-222-333-513", parsed.getGroup().toString());
        assertEquals("S-1-5-21-111-222-333-512", parsed.getDacl().getAce(0).getSid().toString());

        // Single ACE parsing with curly-braced GUIDs and VW/DE right aliases
        final ACE single = ACE.parse("(OA;CI;VWDE;{bf9679c0-0de6-11d0-a285-00aa003049e2};;PS)");
        assertEquals(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, single.getType());
        assertTrue(single.getRights().getObjectRights().contains(ObjectRight.SW));
        assertTrue(single.getRights().getObjectRights().contains(ObjectRight.SD));
        assertTrue(AdSchemaGuid.ATTR_MEMBER.matches(single.getObjectType()));
        assertEquals(WellKnownSid.PRINCIPAL_SELF.toSid(), single.getSid());

        // NO_ACCESS_CONTROL section
        final SDDL noDacl = SddlParser.parse("O:BAD:NO_ACCESS_CONTROL");
        assertNotNull(noDacl.getOwner());
        assertNull(noDacl.getDacl());

        // Invalid SDDL throws IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () -> SDDL.parse("INVALID"));
        assertThrows(IllegalArgumentException.class, () -> ACE.parse("(A;CI;GA)"));
    }
}

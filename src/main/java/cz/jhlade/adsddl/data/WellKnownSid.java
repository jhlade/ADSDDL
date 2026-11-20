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
package cz.jhlade.adsddl.data;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.tirasa.adsddl.ntsd.SID;

/**
 * Well-known Security Identifiers (SIDs) and two-letter SDDL SID aliases ([MS-DTYP] section 2.4.2.4 &amp; 2.5.1.1).
 * <p>
 * Domain-relative well-known SIDs (such as {@link #DOMAIN_ADMINS} or {@link #ACCOUNT_OPERATORS}) can be instantiated
 * for a specific domain SID via {@link #toSid(SID)}. Universal/built-in SIDs can be instantiated directly via
 * {@link #toSid()}.
 * </p>
 */
public enum WellKnownSid {

    /**
     * Everyone / World ({@code S-1-1-0}, SDDL alias {@code WD}).
     */
    EVERYONE("WD", "S-1-1-0", false, 0),

    /**
     * Creator Owner ({@code S-1-3-0}, SDDL alias {@code CO}).
     */
    CREATOR_OWNER("CO", "S-1-3-0", false, 0),

    /**
     * Creator Group ({@code S-1-3-1}, SDDL alias {@code CG}).
     */
    CREATOR_GROUP("CG", "S-1-3-1", false, 1),

    /**
     * Network ({@code S-1-5-2}, SDDL alias {@code NU}).
     */
    NETWORK("NU", "S-1-5-2", false, 2),

    /**
     * Interactive ({@code S-1-5-4}, SDDL alias {@code IU}).
     */
    INTERACTIVE("IU", "S-1-5-4", false, 4),

    /**
     * Service ({@code S-1-5-6}, SDDL alias {@code SU}).
     */
    SERVICE("SU", "S-1-5-6", false, 6),

    /**
     * Anonymous ({@code S-1-5-7}, SDDL alias {@code AN}).
     */
    ANONYMOUS("AN", "S-1-5-7", false, 7),

    /**
     * Enterprise Domain Controllers ({@code S-1-5-9}, SDDL alias {@code ED}).
     */
    ENTERPRISE_DOMAIN_CONTROLLERS("ED", "S-1-5-9", false, 9),

    /**
     * Principal Self ({@code S-1-5-10}, SDDL alias {@code PS}).
     */
    PRINCIPAL_SELF("PS", "S-1-5-10", false, 10),

    /**
     * Authenticated Users ({@code S-1-5-11}, SDDL alias {@code AU}).
     */
    AUTHENTICATED_USERS("AU", "S-1-5-11", false, 11),

    /**
     * Restricted Code ({@code S-1-5-12}, SDDL alias {@code RC}).
     */
    RESTRICTED_CODE("RC", "S-1-5-12", false, 12),

    /**
     * Local System ({@code S-1-5-18}, SDDL alias {@code SY}).
     */
    LOCAL_SYSTEM("SY", "S-1-5-18", false, 18),

    /**
     * Local Service ({@code S-1-5-19}, SDDL alias {@code LS}).
     */
    LOCAL_SERVICE("LS", "S-1-5-19", false, 19),

    /**
     * Network Service ({@code S-1-5-20}, SDDL alias {@code NS}).
     */
    NETWORK_SERVICE("NS", "S-1-5-20", false, 20),

    /**
     * Built-in Administrators ({@code S-1-5-32-544}, SDDL alias {@code BA}).
     */
    BUILTIN_ADMINISTRATORS("BA", "S-1-5-32-544", false, 544),

    /**
     * Built-in Users ({@code S-1-5-32-545}, SDDL alias {@code BU}).
     */
    BUILTIN_USERS("BU", "S-1-5-32-545", false, 545),

    /**
     * Built-in Guests ({@code S-1-5-32-546}, SDDL alias {@code BG}).
     */
    BUILTIN_GUESTS("BG", "S-1-5-32-546", false, 546),

    /**
     * Account Operators ({@code S-1-5-32-548}, SDDL alias {@code AO}).
     */
    ACCOUNT_OPERATORS("AO", "S-1-5-32-548", false, 548),

    /**
     * Server Operators ({@code S-1-5-32-549}, SDDL alias {@code SO}).
     */
    SERVER_OPERATORS("SO", "S-1-5-32-549", false, 549),

    /**
     * Printer Operators ({@code S-1-5-32-550}, SDDL alias {@code PO}).
     */
    PRINTER_OPERATORS("PO", "S-1-5-32-550", false, 550),

    /**
     * Backup Operators ({@code S-1-5-32-551}, SDDL alias {@code BO}).
     */
    BACKUP_OPERATORS("BO", "S-1-5-32-551", false, 551),

    /**
     * Replicator ({@code S-1-5-32-552}, SDDL alias {@code RE}).
     */
    REPLICATOR("RE", "S-1-5-32-552", false, 552),

    /**
     * Pre-Windows 2000 Compatible Access ({@code S-1-5-32-554}, SDDL alias {@code RU}).
     */
    PRE_WIN2K_COMPATIBLE_ACCESS("RU", "S-1-5-32-554", false, 554),

    /**
     * Remote Desktop Users ({@code S-1-5-32-555}, SDDL alias {@code RD}).
     */
    REMOTE_DESKTOP_USERS("RD", "S-1-5-32-555", false, 555),

    /**
     * Network Configuration Operators ({@code S-1-5-32-556}, SDDL alias {@code NO}).
     */
    NETWORK_CONFIGURATION_OPERATORS("NO", "S-1-5-32-556", false, 556),

    // --- Domain-relative Well-Known SIDs (require Domain SID + RID) ---

    /**
     * Domain Administrator ({@code <Domain-SID>-500}, SDDL alias {@code LA}).
     */
    DOMAIN_ADMINISTRATOR("LA", null, true, 500),

    /**
     * Domain Guest ({@code <Domain-SID>-501}, SDDL alias {@code LG}).
     */
    DOMAIN_GUEST("LG", null, true, 501),

    /**
     * Domain Admins ({@code <Domain-SID>-512}, SDDL alias {@code DA}).
     */
    DOMAIN_ADMINS("DA", null, true, 512),

    /**
     * Domain Users ({@code <Domain-SID>-513}, SDDL alias {@code DU}).
     */
    DOMAIN_USERS("DU", null, true, 513),

    /**
     * Domain Guests ({@code <Domain-SID>-514}, SDDL alias {@code DG}).
     */
    DOMAIN_GUESTS("DG", null, true, 514),

    /**
     * Domain Computers ({@code <Domain-SID>-515}, SDDL alias {@code DC}).
     */
    DOMAIN_COMPUTERS("DC", null, true, 515),

    /**
     * Domain Controllers ({@code <Domain-SID>-516}, SDDL alias {@code DD}).
     */
    DOMAIN_CONTROLLERS("DD", null, true, 516),

    /**
     * Cert Publishers ({@code <Domain-SID>-517}, SDDL alias {@code CA}).
     */
    CERT_PUBLISHERS("CA", null, true, 517),

    /**
     * Schema Admins ({@code <Domain-SID>-518}, SDDL alias {@code SA}).
     */
    SCHEMA_ADMINS("SA", null, true, 518),

    /**
     * Enterprise Admins ({@code <Domain-SID>-519}, SDDL alias {@code EA}).
     */
    ENTERPRISE_ADMINS("EA", null, true, 519),

    /**
     * Group Policy Creator Owners ({@code <Domain-SID>-520}, SDDL alias {@code PA}).
     */
    GROUP_POLICY_CREATOR_OWNERS("PA", null, true, 520),

    /**
     * Read-only Domain Controllers ({@code <Domain-SID>-521}, SDDL alias {@code RO}).
     */
    READONLY_DOMAIN_CONTROLLERS("RO", null, true, 521),

    /**
     * RAS and IAS Servers ({@code <Domain-SID>-553}, SDDL alias {@code RS}).
     */
    RAS_SERVERS("RS", null, true, 553);

    private static final Map<String, WellKnownSid> BY_ALIAS = new HashMap<>(48);

    static {
        for (WellKnownSid wks : values()) {
            BY_ALIAS.put(wks.sddlAlias, wks);
        }
    }

    private final String sddlAlias;

    private final String sidString;

    private final boolean domainRelative;

    private final long rid;

    private final byte[] precomputedBytes;

    WellKnownSid(
            final String sddlAlias,
            final String sidString,
            final boolean domainRelative,
            final long rid) {
        this.sddlAlias = sddlAlias;
        this.sidString = sidString;
        this.domainRelative = domainRelative;
        this.rid = rid;
        this.precomputedBytes = sidString == null ? null : SID.parse(sidString).toByteArray();
    }

    /**
     * Gets the two-letter SDDL alias (e.g. {@code "WD"}, {@code "PS"}, {@code "BA"}, {@code "DA"}).
     *
     * @return SDDL alias.
     */
    public String getSddlAlias() {
        return sddlAlias;
    }

    /**
     * Gets the static SID string for universal/built-in SIDs, or {@code null} if domain-relative.
     *
     * @return SID string or null.
     */
    public String getSidString() {
        return sidString;
    }

    /**
     * Returns true if this well-known SID is relative to a specific domain SID (requires a domain prefix + RID).
     *
     * @return true if domain-relative.
     */
    public boolean isDomainRelative() {
        return domainRelative;
    }

    /**
     * Gets the Relative Identifier (RID) of this principal.
     *
     * @return RID.
     */
    public long getRid() {
        return rid;
    }

    /**
     * Creates a fresh {@link SID} instance for non-domain-relative well-known SIDs.
     *
     * @return new {@link SID} instance.
     * @throws IllegalStateException if this SID is domain-relative (use {@link #toSid(SID)} instead).
     */
    public SID toSid() {
        if (domainRelative) {
            throw new IllegalStateException(name() + " (" + sddlAlias + ") requires a domain SID");
        }
        return SID.parse(precomputedBytes);
    }

    /**
     * Creates a fresh {@link SID} instance, appending the RID to {@code domainSid} if this SID is domain-relative.
     *
     * @param domainSid domain SID (e.g. {@code S-1-5-21-X-Y-Z}), or null for universal/built-in SIDs.
     * @return new {@link SID} instance.
     */
    public SID toSid(final SID domainSid) {
        if (!domainRelative) {
            return toSid();
        }
        if (domainSid == null) {
            throw new IllegalArgumentException(name() + " (" + sddlAlias + ") requires a non-null domain SID");
        }
        final SID res = SID.newInstance(domainSid.getIdentifierAuthority());
        res.setRevision(domainSid.getRevision());
        final List<byte[]> subs = domainSid.getSubAuthorities();
        // If a full user/group SID (5 sub-authorities: 21-A-B-C-RID) was passed instead of the 4-sub-authority domain SID,
        // take the first 4 sub-authorities (21-A-B-C)
        final int count = (subs.size() == 5 && Arrays.equals(subs.get(0), new byte[] { 0, 0, 0, 21 }))
                ? 4
                : subs.size();
        for (int i = 0; i < count; i++) {
            res.addSubAuthority(subs.get(i));
        }
        res.addSubAuthority(rid);
        return res;
    }

    /**
     * Checks whether the given {@link SID} matches this well-known SID.
     * For domain-relative SIDs, checks that the SID is under {@code S-1-5-21-*-*-*-<rid>}.
     *
     * @param sid SID to check.
     * @return true if it matches.
     */
    public boolean matches(final SID sid) {
        if (sid == null) {
            return false;
        }
        if (!domainRelative) {
            return Arrays.equals(precomputedBytes, sid.toByteArray());
        }
        final List<byte[]> subs = sid.getSubAuthorities();
        if (subs.size() != 5 || !Arrays.equals(sid.getIdentifierAuthority(), new byte[] { 0, 0, 0, 0, 0, 5 })) {
            return false;
        }
        final byte[] first = subs.get(0);
        if (first[0] != 0 || first[1] != 0 || first[2] != 0 || first[3] != 21) {
            return false;
        }
        final byte[] last = subs.get(4);
        final long actualRid = ((last[0] & 0xFFL) << 24)
                | ((last[1] & 0xFFL) << 16)
                | ((last[2] & 0xFFL) << 8)
                | (last[3] & 0xFFL);
        return actualRid == rid;
    }

    /**
     * Looks up a {@link WellKnownSid} by its two-letter SDDL alias (case-insensitive).
     *
     * @param alias two-letter SDDL alias (e.g. {@code "WD"}, {@code "PS"}).
     * @return matching {@link WellKnownSid}, or {@code null} if unknown.
     */
    public static WellKnownSid fromSddlAlias(final String alias) {
        return alias == null ? null : BY_ALIAS.get(alias.toUpperCase());
    }

    /**
     * Looks up a {@link WellKnownSid} matching the given {@link SID}.
     *
     * @param sid SID instance.
     * @return matching {@link WellKnownSid}, or {@code null} if not a well-known SID.
     */
    public static WellKnownSid fromSid(final SID sid) {
        if (sid == null) {
            return null;
        }
        for (WellKnownSid wks : values()) {
            if (wks.matches(sid)) {
                return wks;
            }
        }
        return null;
    }
}

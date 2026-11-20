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
package cz.jhlade.adsddl.sddl;

import cz.jhlade.adsddl.data.WellKnownSid;
import java.util.ArrayList;
import java.util.List;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.AclRevision;
import net.tirasa.adsddl.ntsd.data.SddlControlFlag;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;

/**
 * Rigorous, single-pass, zero-regex parser and formatter for the Microsoft Security Descriptor Description Language
 * (SDDL) as specified in [MS-DTYP] section 2.5.1.
 * <p>
 * Supports:
 * <ul>
 *   <li>All four top-level security descriptor sections in any order: {@code O:<owner>}, {@code G:<group>},
 *       {@code D:<dacl_flags>(<ace>)...}, {@code S:<sacl_flags>(<ace>)...}</li>
 *   <li>ACL control flags: {@code P} (Protected), {@code AR} (Auto-Inherit Required), {@code AI} (Auto-Inherited)</li>
 *   <li>All 6-field ACE strings:
 *       {@code (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)}</li>
 *   <li>Conditional / Callback ACEs with 7th field:
 *       {@code (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute_or_cond))}</li>
 *   <li>Standard two-letter SDDL rights ({@code GA, GR, GW, GX, RC, SD, WD, WO, RP, WP, CC, DC, LC, SW, LO, DT, CR,
 *       FA, FR, FW, FX, KA, KR, KW, KX, NR, NW, NX}), hexadecimal masks ({@code 0x...}), and ADSDDL bracketed
 *       custom decimal masks ({@code [123]})</li>
 *   <li>Literal SID strings ({@code S-1-...}) as well as all 38 two-letter {@link WellKnownSid} aliases
 *       ({@code WD, PS, SY, BA, AU, AO, DA, DU, ...}) with domain SID resolution</li>
 * </ul>
 */
public final class SddlParser {

    // Composite file/registry/mandatory-label SDDL right constants ([MS-DTYP] 2.5.1.1)
    private static final int FILE_ALL_ACCESS = 0x001F01FF; // FA
    private static final int FILE_GENERIC_EXECUTE = 0x001200A0; // FX
    private static final int FILE_GENERIC_WRITE = 0x00120116; // FW
    private static final int FILE_GENERIC_READ = 0x00120089; // FR
    private static final int KEY_ALL_ACCESS = 0x000F003F; // KA
    private static final int KEY_READ = 0x00020019; // KR
    private static final int KEY_EXECUTE = 0x00020019; // KX
    private static final int KEY_WRITE = 0x00020006; // KW
    private static final int SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x00000001; // NW
    private static final int SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0x00000002; // NR
    private static final int SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP = 0x00000004; // NX

    private SddlParser() {
    }

    /**
     * Parses an SDDL string into an {@link SDDL} security descriptor instance.
     *
     * @param sddlString SDDL string (e.g. {@code "O:BAG:SYD:PAI(A;;GA;;;BA)"}).
     * @return parsed {@link SDDL} instance.
     * @throws IllegalArgumentException if the SDDL string is malformed or contains domain-relative aliases without
     *                                  a domain SID.
     */
    public static SDDL parse(final String sddlString) {
        return parse(sddlString, null);
    }

    /**
     * Parses an SDDL string into an {@link SDDL} security descriptor instance, resolving any domain-relative
     * well-known SID aliases (such as {@code DA}, {@code DU}, {@code EA}, {@code LA}) against {@code domainSid}.
     * <p>
     * If {@code domainSid} is {@code null} and the SDDL string contains an explicit literal domain SID in the
     * {@code O:} or {@code G:} section (e.g. {@code O:S-1-5-21-A-B-C-500}), that domain prefix is automatically
     * inferred for subsequent domain-relative aliases in the DACL/SACL.
     * </p>
     *
     * @param sddlString SDDL string.
     * @param domainSid domain SID (e.g. {@code S-1-5-21-X-Y-Z}), or {@code null}.
     * @return parsed {@link SDDL} instance.
     */
    public static SDDL parse(final String sddlString, final SID domainSid) {
        if (sddlString == null) {
            throw new IllegalArgumentException("SDDL string must not be null");
        }
        final SDDL sddl = new SDDL();
        final int len = sddlString.length();
        int pos = skipWhitespace(sddlString, 0, len);
        SID effectiveDomainSid = domainSid != null ? domainSid : inferDomainSidFromString(sddlString);

        while (pos < len) {
            if (pos + 1 >= len || sddlString.charAt(pos + 1) != ':') {
                throw new IllegalArgumentException(
                        "Expected SDDL section header ('O:', 'G:', 'D:', or 'S:') at index " + pos
                        + " in: " + sddlString);
            }
            final char section = Character.toUpperCase(sddlString.charAt(pos));
            pos += 2; // skip '<X>:'

            switch (section) {
                case 'O': {
                    final int sidEnd = findNextSectionOrEnd(sddlString, pos, len);
                    final SID owner = parseSidSegment(sddlString, pos, sidEnd, effectiveDomainSid);
                    sddl.setOwner(owner);
                    pos = sidEnd;
                    break;
                }
                case 'G': {
                    final int sidEnd = findNextSectionOrEnd(sddlString, pos, len);
                    final SID group = parseSidSegment(sddlString, pos, sidEnd, effectiveDomainSid);
                    sddl.setGroup(group);
                    pos = sidEnd;
                    break;
                }
                case 'D': {
                    pos = parseAclSection(sddlString, pos, len, sddl, true, effectiveDomainSid);
                    break;
                }
                case 'S': {
                    pos = parseAclSection(sddlString, pos, len, sddl, false, effectiveDomainSid);
                    break;
                }
                default:
                    throw new IllegalArgumentException(
                            "Unknown SDDL section '" + section + ":' at index " + (pos - 2));
            }
            pos = skipWhitespace(sddlString, pos, len);
        }

        return sddl;
    }

    /**
     * Parses a single SDDL ACE string {@code "(type;flags;rights;obj_guid;inh_guid;sid)"} into an {@link ACE}.
     *
     * @param aceString SDDL ACE string (with or without surrounding parentheses).
     * @param domainSid optional domain SID for resolving domain-relative SID aliases.
     * @return parsed {@link ACE}.
     */
    public static ACE parseAce(final String aceString, final SID domainSid) {
        if (aceString == null || aceString.isEmpty()) {
            throw new IllegalArgumentException("ACE string must not be null or empty");
        }
        int start = skipWhitespace(aceString, 0, aceString.length());
        int end = trimTrailingWhitespace(aceString, start, aceString.length());
        if (start < end && aceString.charAt(start) == '(' && aceString.charAt(end - 1) == ')') {
            start++;
            end--;
        }
        return parseAceBody(aceString, start, end, domainSid);
    }

    /**
     * Formats an {@link SDDL} instance into canonical Microsoft SDDL string format, using standard two-letter
     * {@link WellKnownSid} aliases (e.g. {@code WD}, {@code PS}, {@code SY}, {@code BA}) where applicable
     * and accurate ACL control flags ({@code P}, {@code AR}, {@code AI}).
     *
     * @param sddl security descriptor.
     * @param useSidAliases true to format well-known SIDs using their 2-letter SDDL aliases, false to always output
     *                      full {@code S-1-...} strings.
     * @return formatted SDDL string.
     */
    public static String format(final SDDL sddl, final boolean useSidAliases) {
        if (sddl == null) {
            return "";
        }
        final StringBuilder bld = new StringBuilder(256);

        if (sddl.getOwner() != null) {
            bld.append("O:");
            appendSid(bld, sddl.getOwner(), useSidAliases);
        }
        if (sddl.getGroup() != null) {
            bld.append("G:");
            appendSid(bld, sddl.getGroup(), useSidAliases);
        }
        if (sddl.getDacl() != null) {
            bld.append("D:");
            if (sddl.hasControlFlag(SddlControlFlag.SE_DACL_PROTECTED)) {
                bld.append("P");
            }
            if (sddl.hasControlFlag(SddlControlFlag.SE_DACL_AUTO_INHERIT_REQ)) {
                bld.append("AR");
            }
            if (sddl.hasControlFlag(SddlControlFlag.SE_DACL_AUTO_INHERITED)) {
                bld.append("AI");
            }
            // Backward compatibility: if no DACL control flag bit was set on a legacy SDDL object,
            // ACL.toString() historically prefixed 'P'
            if (!sddl.hasControlFlag(SddlControlFlag.SE_DACL_PROTECTED)
                    && !sddl.hasControlFlag(SddlControlFlag.SE_DACL_AUTO_INHERIT_REQ)
                    && !sddl.hasControlFlag(SddlControlFlag.SE_DACL_AUTO_INHERITED)
                    && !useSidAliases) {
                bld.append("P");
            }
            for (ACE ace : sddl.getDacl().getAces()) {
                appendAce(bld, ace, useSidAliases);
            }
        }
        if (sddl.getSacl() != null) {
            bld.append("S:");
            if (sddl.hasControlFlag(SddlControlFlag.SE_SACL_PROTECTED)) {
                bld.append("P");
            }
            if (sddl.hasControlFlag(SddlControlFlag.SE_SACL_AUTO_INHERIT_REQ)) {
                bld.append("AR");
            }
            if (sddl.hasControlFlag(SddlControlFlag.SE_SACL_AUTO_INHERITED)) {
                bld.append("AI");
            }
            if (!sddl.hasControlFlag(SddlControlFlag.SE_SACL_PROTECTED)
                    && !sddl.hasControlFlag(SddlControlFlag.SE_SACL_AUTO_INHERIT_REQ)
                    && !sddl.hasControlFlag(SddlControlFlag.SE_SACL_AUTO_INHERITED)
                    && !useSidAliases) {
                bld.append("P");
            }
            for (ACE ace : sddl.getSacl().getAces()) {
                appendAce(bld, ace, useSidAliases);
            }
        }

        return bld.toString();
    }

    private static void appendSid(final StringBuilder bld, final SID sid, final boolean useSidAliases) {
        if (useSidAliases) {
            final WellKnownSid wks = WellKnownSid.fromSid(sid);
            if (wks != null) {
                bld.append(wks.getSddlAlias());
                return;
            }
        }
        bld.append(sid.toString());
    }

    private static void appendAce(final StringBuilder bld, final ACE ace, final boolean useSidAliases) {
        bld.append('(');
        if (ace.getType() != null) {
            bld.append(ace.getType().toString());
        }
        bld.append(';');
        for (AceFlag flag : ace.getFlags()) {
            bld.append(flag.toString());
        }
        bld.append(';');
        final AceRights rights = ace.getRights();
        if (rights != null) {
            for (ObjectRight right : rights.getObjectRights()) {
                bld.append(right.name());
            }
            if (rights.getOthers() != 0) {
                if (useSidAliases && rights.getObjectRights().isEmpty()) {
                    bld.append("0x").append(Long.toHexString(rights.getOthers()));
                } else {
                    bld.append('[').append(rights.getOthers()).append(']');
                }
            }
        }
        bld.append(';');
        if (ace.getObjectType() != null) {
            bld.append(GUID.getGuidAsString(ace.getObjectType()));
        }
        bld.append(';');
        if (ace.getInheritedObjectType() != null) {
            bld.append(GUID.getGuidAsString(ace.getInheritedObjectType()));
        }
        bld.append(';');
        if (ace.getSid() != null) {
            appendSid(bld, ace.getSid(), useSidAliases);
        }
        bld.append(')');
    }

    private static int parseAclSection(
            final String str,
            final int start,
            final int len,
            final SDDL sddl,
            final boolean isDacl,
            final SID domainSid) {
        int pos = skipWhitespace(str, start, len);

        // Parse optional ACL control flags: P, AR, AI, NO_ACCESS_CONTROL
        if (regionMatchesIgnoreCase(str, pos, len, "NO_ACCESS_CONTROL")) {
            pos += "NO_ACCESS_CONTROL".length();
            if (isDacl) {
                sddl.setDacl(null);
            } else {
                sddl.setSacl(null);
            }
            return pos;
        }

        while (pos < len) {
            final char c = Character.toUpperCase(str.charAt(pos));
            if (c == 'P') {
                sddl.addControlFlags(isDacl
                        ? SddlControlFlag.SE_DACL_PROTECTED
                        : SddlControlFlag.SE_SACL_PROTECTED);
                pos++;
            } else if (c == 'A' && pos + 1 < len) {
                final char c2 = Character.toUpperCase(str.charAt(pos + 1));
                if (c2 == 'R') {
                    sddl.addControlFlags(isDacl
                            ? SddlControlFlag.SE_DACL_AUTO_INHERIT_REQ
                            : SddlControlFlag.SE_SACL_AUTO_INHERIT_REQ);
                    pos += 2;
                } else if (c2 == 'I') {
                    sddl.addControlFlags(isDacl
                            ? SddlControlFlag.SE_DACL_AUTO_INHERITED
                            : SddlControlFlag.SE_SACL_AUTO_INHERITED);
                    pos += 2;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        final ACL acl = new ACL();
        boolean hasObjectAce = false;

        pos = skipWhitespace(str, pos, len);
        while (pos < len && str.charAt(pos) == '(') {
            final int closeParen = findMatchingCloseParen(str, pos, len);
            final ACE ace = parseAceBody(str, pos + 1, closeParen, domainSid);
            if (ACE.isObjectAceType(ace.getType())) {
                hasObjectAce = true;
            }
            acl.getAces().add(ace);
            pos = skipWhitespace(str, closeParen + 1, len);
        }

        acl.setRevision(hasObjectAce ? AclRevision.ACL_REVISION_DS : AclRevision.ACL_REVISION);
        if (isDacl) {
            sddl.setDacl(acl);
        } else {
            sddl.setSacl(acl);
        }
        return pos;
    }

    private static int findMatchingCloseParen(final String str, final int openParenPos, final int len) {
        int depth = 0;
        for (int i = openParenPos; i < len; i++) {
            final char c = str.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        throw new IllegalArgumentException(
                "Unclosed ACE parenthesis starting at index " + openParenPos + " in: " + str);
    }

    private static ACE parseAceBody(
            final String str,
            final int start,
            final int end,
            final SID domainSid) {
        // An ACE body has 6 semicolon-separated fields (or 7 for callback/resource-attribute ACEs):
        // 0: ace_type
        // 1: ace_flags
        // 2: rights
        // 3: object_guid
        // 4: inherit_object_guid
        // 5: account_sid
        // [6: optional conditional / resource attribute data]
        final int[] semi = new int[6];
        int semiCount = 0;
        int parenDepth = 0;
        for (int i = start; i < end; i++) {
            final char c = str.charAt(i);
            if (c == '(') {
                parenDepth++;
            } else if (c == ')') {
                parenDepth--;
            } else if (c == ';' && parenDepth == 0) {
                if (semiCount < 6) {
                    semi[semiCount] = i;
                }
                semiCount++;
            }
        }

        if (semiCount < 5) {
            throw new IllegalArgumentException(
                    "Invalid SDDL ACE (expected at least 6 semicolon-separated fields): ("
                    + str.substring(start, end) + ")");
        }

        final AceType type = parseAceType(str, start, semi[0]);
        final List<AceFlag> flags = parseAceFlags(str, semi[0] + 1, semi[1]);
        final AceRights rights = parseAceRights(str, semi[1] + 1, semi[2]);
        final byte[] objectType = parseOptionalGuid(str, semi[2] + 1, semi[3]);
        final byte[] inheritedObjectType = parseOptionalGuid(str, semi[3] + 1, semi[4]);
        final int sidEnd = semiCount >= 6 ? semi[5] : end;
        final SID sid = parseSidSegment(str, semi[4] + 1, sidEnd, domainSid);

        final ACE ace = ACE.newInstance(type);
        ace.setFlags(flags);
        ace.setRights(rights);

        if (ACE.isObjectAceType(type) || objectType != null || inheritedObjectType != null) {
            final AceObjectFlags objFlags = new AceObjectFlags();
            if (objectType != null) {
                objFlags.addFlag(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT);
            }
            if (inheritedObjectType != null) {
                objFlags.addFlag(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT);
            }
            ace.setObjectFlags(objFlags);
            if (objectType != null) {
                ace.setObjectType(objectType);
            }
            if (inheritedObjectType != null) {
                ace.setInheritedObjectType(inheritedObjectType);
            }
        }

        ace.setSid(sid);
        return ace;
    }

    private static AceType parseAceType(final String str, final int start, final int end) {
        final int s = skipWhitespace(str, start, end);
        final int e = trimTrailingWhitespace(str, s, end);
        final int len = e - s;
        if (len == 1) {
            final char c0 = Character.toUpperCase(str.charAt(s));
            if (c0 == 'A') {
                return AceType.ACCESS_ALLOWED_ACE_TYPE;
            }
            if (c0 == 'D') {
                return AceType.ACCESS_DENIED_ACE_TYPE;
            }
        } else if (len == 2) {
            final char c0 = Character.toUpperCase(str.charAt(s));
            final char c1 = Character.toUpperCase(str.charAt(s + 1));
            for (AceType type : AceType.values()) {
                final String code = type.toString();
                if (code.length() == 2 && code.charAt(0) == c0 && code.charAt(1) == c1) {
                    return type;
                }
            }
        }
        final String token = str.substring(s, e);
        for (AceType type : AceType.values()) {
            if (type.name().equalsIgnoreCase(token)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown SDDL ACE type: '" + token + "'");
    }

    private static List<AceFlag> parseAceFlags(final String str, final int start, final int end) {
        final List<AceFlag> res = new ArrayList<>(4);
        int pos = skipWhitespace(str, start, end);
        final int limit = trimTrailingWhitespace(str, pos, end);

        if (pos + 2 <= limit && str.charAt(pos) == '0'
                && (str.charAt(pos + 1) == 'x' || str.charAt(pos + 1) == 'X')) {
            final byte mask = (byte) parseUnsignedHex(str, pos + 2, limit);
            return AceFlag.parseValue(mask);
        }

        while (pos < limit) {
            pos = skipWhitespace(str, pos, limit);
            if (pos >= limit) {
                break;
            }
            if (pos + 2 > limit) {
                throw new IllegalArgumentException(
                        "Invalid SDDL ACE flag token at index " + pos + " in: " + str.substring(start, end));
            }
            final char c0 = Character.toUpperCase(str.charAt(pos));
            final char c1 = Character.toUpperCase(str.charAt(pos + 1));
            final AceFlag flag = matchAceFlag(c0, c1);
            if (flag == null) {
                throw new IllegalArgumentException("Unknown SDDL ACE flag: '" + c0 + c1 + "'");
            }
            if (!res.contains(flag)) {
                res.add(flag);
            }
            pos += 2;
        }
        return res;
    }

    private static AceFlag matchAceFlag(final char c0, final char c1) {
        switch (c0) {
            case 'C':
                return c1 == 'I' ? AceFlag.CONTAINER_INHERIT_ACE : null;
            case 'O':
                return c1 == 'I' ? AceFlag.OBJECT_INHERIT_ACE : null;
            case 'N':
                return c1 == 'P' ? AceFlag.NO_PROPAGATE_INHERIT_ACE : null;
            case 'I':
                if (c1 == 'O') {
                    return AceFlag.INHERIT_ONLY_ACE;
                }
                if (c1 == 'D') {
                    return AceFlag.INHERITED_ACE;
                }
                return null;
            case 'S':
                return c1 == 'A' ? AceFlag.SUCCESSFUL_ACCESS_ACE_FLAG : null;
            case 'F':
                return c1 == 'A' ? AceFlag.FAILED_ACCESS_ACE_FLAG : null;
            default:
                return null;
        }
    }

    private static AceRights parseAceRights(final String str, final int start, final int end) {
        int pos = skipWhitespace(str, start, end);
        final int limit = trimTrailingWhitespace(str, pos, end);
        if (pos >= limit) {
            return new AceRights();
        }

        // Hexadecimal rights mask: 0x...
        if (pos + 2 <= limit && str.charAt(pos) == '0'
                && (str.charAt(pos + 1) == 'x' || str.charAt(pos + 1) == 'X')) {
            final int mask = (int) parseUnsignedHex(str, pos + 2, limit);
            return AceRights.parseValue(mask);
        }

        int totalMask = 0;
        while (pos < limit) {
            pos = skipWhitespace(str, pos, limit);
            if (pos >= limit) {
                break;
            }
            // ADSDDL bracketed decimal custom mask: [12345]
            if (str.charAt(pos) == '[') {
                final int closeBracket = str.indexOf(']', pos + 1);
                if (closeBracket < 0 || closeBracket >= limit) {
                    throw new IllegalArgumentException(
                            "Unclosed '[' in ACE rights: " + str.substring(start, end));
                }
                final long customBits = parseUnsignedDec(str, pos + 1, closeBracket);
                totalMask |= (int) customBits;
                pos = closeBracket + 1;
                continue;
            }

            if (pos + 2 > limit) {
                throw new IllegalArgumentException(
                        "Invalid SDDL ACE right token at index " + pos + " in: " + str.substring(start, end));
            }
            final char c0 = Character.toUpperCase(str.charAt(pos));
            final char c1 = Character.toUpperCase(str.charAt(pos + 1));
            totalMask |= resolveRightMask(c0, c1);
            pos += 2;
        }

        return AceRights.parseValue(totalMask);
    }

    private static int resolveRightMask(final char c0, final char c1) {
        // Check standard ObjectRight enum values first
        for (ObjectRight right : ObjectRight.values()) {
            final String name = right.name();
            if (name.length() == 2 && name.charAt(0) == c0 && name.charAt(1) == c1) {
                return right.getValue();
            }
        }
        // Check composite / alias SDDL right codes ([MS-DTYP] 2.5.1.1)
        if (c0 == 'V' && c1 == 'W') {
            return ObjectRight.SW.getValue(); // VW (Validated Write) is an alias for SW (ADS_RIGHT_DS_SELF)
        }
        if (c0 == 'D' && c1 == 'E') {
            return ObjectRight.SD.getValue(); // DE (Delete) is an alias for SD (STANDARD_DELETE)
        }
        if (c0 == 'F') {
            if (c1 == 'A') {
                return FILE_ALL_ACCESS;
            }
            if (c1 == 'X') {
                return FILE_GENERIC_EXECUTE;
            }
            if (c1 == 'W') {
                return FILE_GENERIC_WRITE;
            }
            if (c1 == 'R') {
                return FILE_GENERIC_READ;
            }
        }
        if (c0 == 'K') {
            if (c1 == 'A') {
                return KEY_ALL_ACCESS;
            }
            if (c1 == 'R') {
                return KEY_READ;
            }
            if (c1 == 'X') {
                return KEY_EXECUTE;
            }
            if (c1 == 'W') {
                return KEY_WRITE;
            }
        }
        if (c0 == 'N') {
            if (c1 == 'W') {
                return SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
            }
            if (c1 == 'R') {
                return SYSTEM_MANDATORY_LABEL_NO_READ_UP;
            }
            if (c1 == 'X') {
                return SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
            }
        }
        throw new IllegalArgumentException("Unknown SDDL ACE right code: '" + c0 + c1 + "'");
    }

    private static byte[] parseOptionalGuid(final String str, final int start, final int end) {
        int s = skipWhitespace(str, start, end);
        int e = trimTrailingWhitespace(str, s, end);
        if (s >= e) {
            return null;
        }
        if (str.charAt(s) == '{' && str.charAt(e - 1) == '}') {
            s++;
            e--;
        }
        return GUID.getGuidAsByteArray(str.substring(s, e));
    }

    private static SID parseSidSegment(
            final String str,
            final int start,
            final int end,
            final SID domainSid) {
        final int s = skipWhitespace(str, start, end);
        final int e = trimTrailingWhitespace(str, s, end);
        if (s >= e) {
            return null;
        }
        final int len = e - s;
        if (len >= 5 && (str.charAt(s) == 'S' || str.charAt(s) == 's') && str.charAt(s + 1) == '-') {
            return SID.parse(str.substring(s, e));
        }
        if (len == 2) {
            final String alias = str.substring(s, e);
            final WellKnownSid wks = WellKnownSid.fromSddlAlias(alias);
            if (wks != null) {
                return wks.toSid(domainSid);
            }
        }
        throw new IllegalArgumentException("Invalid SDDL SID or unknown SID alias: '" + str.substring(s, e) + "'");
    }

    private static int findNextSectionOrEnd(final String str, final int start, final int len) {
        for (int i = start; i < len - 1; i++) {
            if (str.charAt(i + 1) == ':') {
                final char c = Character.toUpperCase(str.charAt(i));
                if (c == 'O' || c == 'G' || c == 'D' || c == 'S') {
                    return i;
                }
            }
        }
        return len;
    }

    private static SID inferDomainSidFromString(final String sddlString) {
        int idx = sddlString.indexOf("S-1-5-21-");
        if (idx < 0) {
            idx = sddlString.indexOf("s-1-5-21-");
        }
        if (idx < 0) {
            return null;
        }
        int end = idx + "S-1-5-21-".length();
        final int len = sddlString.length();
        while (end < len) {
            final char c = sddlString.charAt(end);
            if ((c >= '0' && c <= '9') || c == '-') {
                end++;
            } else {
                break;
            }
        }
        try {
            final SID candidate = SID.parse(sddlString.substring(idx, end));
            return isDomainPrincipalSid(candidate) ? candidate : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isDomainPrincipalSid(final SID sid) {
        if (sid == null || sid.getSubAuthorityCount() < 4) {
            return false;
        }
        final byte[] auth = sid.getIdentifierAuthority();
        if (auth == null || auth[0] != 0 || auth[1] != 0 || auth[2] != 0 || auth[3] != 0 || auth[4] != 0 || auth[5] != 5) {
            return false;
        }
        final byte[] firstSub = sid.getSubAuthorities().get(0);
        return firstSub[0] == 0 && firstSub[1] == 0 && firstSub[2] == 0 && firstSub[3] == 21;
    }

    private static boolean regionMatchesIgnoreCase(
            final String str,
            final int offset,
            final int limit,
            final String target) {
        final int tLen = target.length();
        if (offset + tLen > limit) {
            return false;
        }
        return str.regionMatches(true, offset, target, 0, tLen);
    }

    private static long parseUnsignedHex(final String str, final int start, final int end) {
        if (start >= end) {
            throw new IllegalArgumentException("Empty hex number in SDDL");
        }
        long res = 0;
        for (int i = start; i < end; i++) {
            final int nibble = Hex.decodeNibble(str.charAt(i));
            if (nibble < 0) {
                throw new IllegalArgumentException("Invalid hex character '" + str.charAt(i) + "' in SDDL");
            }
            res = (res << 4) | nibble;
        }
        return res;
    }

    private static long parseUnsignedDec(final String str, final int start, final int end) {
        if (start >= end) {
            throw new IllegalArgumentException("Empty decimal number in SDDL");
        }
        long res = 0;
        for (int i = start; i < end; i++) {
            final char c = str.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("Invalid decimal character '" + c + "' in SDDL");
            }
            res = res * 10 + (c - '0');
        }
        return res;
    }

    private static int skipWhitespace(final String str, final int start, final int limit) {
        int p = start;
        while (p < limit && str.charAt(p) <= ' ') {
            p++;
        }
        return p;
    }

    private static int trimTrailingWhitespace(final String str, final int start, final int end) {
        int p = end;
        while (p > start && str.charAt(p - 1) <= ' ') {
            p--;
        }
        return p;
    }
}

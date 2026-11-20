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
package net.tirasa.adsddl.ntsd;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A security identifier (SID) uniquely identifies a security principal. Each security principal has a unique SID that
 * is issued by a security agent. The agent can be a Windows local system or domain. The agent generates the SID when
 * the security principal is created. The SID can be represented as a character string or as a structure. When
 * represented as strings, for example in documentation or logs, SIDs are expressed as follows:
 *
 * S-1-IdentifierAuthority-SubAuthority1-SubAuthority2-...-SubAuthorityn
 *
 * The top-level issuer is the authority. Each issuer specifies, in an implementation-specific manner, how many integers
 * identify the next issuer.
 *
 * A newly created account store is assigned a 96-bit identifier (a cryptographic strength (pseudo) random number).
 *
 * A newly created security principal in an account store is assigned a 32-bit identifier that is unique within the
 * store.
 *
 * The last item in the series of SubAuthority values is known as the relative identifier (RID). Differences in the RID
 * are what distinguish the different SIDs generated within a domain.
 *
 * Consumers of SIDs SHOULD NOT rely on anything more than that the SID has the appropriate structure.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230371.aspx" target="_top">cc230371</a>
 * @see <a href="https://msdn.microsoft.com/en-us/library/gg465313.aspx" target="_top">gg465313</a>
 */
public class SID {

    /**
     * Logger.
     */
    protected static final Logger LOG = LoggerFactory.getLogger(SID.class);

    /**
     * An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
     */
    private byte revision;

    /**
     * A SID_IDENTIFIER_AUTHORITY (6 bytes) structure that indicates the authority under which the SID was created.
     * It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created
     * by the NT SID authority.
     */
    private byte[] identifierAuthority;

    /**
     * A variable length list of unsigned 32-bit integers that uniquely identifies a principal relative to the
     * IdentifierAuthority.
     */
    private final List<byte[]> subAuthorities;

    SID() {
        subAuthorities = new ArrayList<>();
    }

    /**
     * Instances a new SID with the given identifier authority.
     *
     * @param identifier identifier authority (6 bytes only).
     * @return the SID instance.
     */
    public static SID newInstance(final byte[] identifier) {
        final SID sid = new SID();
        sid.setRevision((byte) 0x01);
        sid.setIdentifierAuthority(identifier);
        return sid;
    }

    /**
     * Instances a SID instance of the given byte array.
     *
     * @param src SID as byte array.
     * @return SID instance.
     */
    public static SID parse(final byte[] src) {
        final ByteBuffer sddlBuffer = ByteBuffer.wrap(src);
        final SID sid = new SID();
        sid.parse(sddlBuffer, 0);
        return sid;
    }

    /**
     * Instances a SID instance from its string representation (e.g. "S-1-5-10" or "S-1-5-21-...").
     * Uses a single-pass character scanner without intermediate regex/array allocations.
     *
     * @param str SID string representation.
     * @return SID instance.
     */
    public static SID parse(final String str) {
        final int len;
        if (str == null || (len = str.length()) < 5) {
            throw new IllegalArgumentException("Invalid SID string: " + str);
        }
        final char c0 = str.charAt(0);
        if ((c0 != 'S' && c0 != 's') || str.charAt(1) != '-') {
            throw new IllegalArgumentException("Invalid SID string: " + str);
        }

        // Parse revision
        int idx = 2;
        int dash = str.indexOf('-', idx);
        if (dash <= idx) {
            throw new IllegalArgumentException("Invalid SID string: " + str);
        }
        final byte rev = (byte) (parseUnsignedSegment(str, idx, dash, 10) & 0xFF);

        // Parse identifier authority
        idx = dash + 1;
        dash = str.indexOf('-', idx);
        final int authEnd = dash < 0 ? len : dash;
        if (authEnd <= idx) {
            throw new IllegalArgumentException("Invalid SID string: " + str);
        }

        final long authVal;
        if (authEnd - idx > 2 && str.charAt(idx) == '0'
                && (str.charAt(idx + 1) == 'x' || str.charAt(idx + 1) == 'X')) {
            authVal = parseUnsignedSegment(str, idx + 2, authEnd, 16);
        } else if (authEnd - idx == 12 && hasHexLetters(str, idx, authEnd)) {
            authVal = parseUnsignedSegment(str, idx, authEnd, 16);
        } else {
            authVal = parseUnsignedSegment(str, idx, authEnd, 10);
        }

        final SID sid = new SID();
        sid.revision = rev;
        sid.identifierAuthority = new byte[] {
            (byte) (authVal >>> 40),
            (byte) (authVal >>> 32),
            (byte) (authVal >>> 24),
            (byte) (authVal >>> 16),
            (byte) (authVal >>> 8),
            (byte) authVal
        };

        // Parse sub-authorities
        while (dash >= 0 && dash < len) {
            idx = dash + 1;
            dash = str.indexOf('-', idx);
            final int subEnd = dash < 0 ? len : dash;
            if (subEnd <= idx) {
                throw new IllegalArgumentException("Invalid SID string: " + str);
            }
            final int sub = (int) parseUnsignedSegment(str, idx, subEnd, 10);
            sid.subAuthorities.add(new byte[] {
                (byte) (sub >>> 24),
                (byte) (sub >>> 16),
                (byte) (sub >>> 8),
                (byte) sub
            });
        }

        return sid;
    }

    private static boolean hasHexLetters(final String str, final int start, final int end) {
        for (int i = start; i < end; i++) {
            final char c = str.charAt(i);
            if (c < '0' || c > '9') {
                return true;
            }
        }
        return false;
    }

    private static long parseUnsignedSegment(final String str, final int start, final int end, final int radix) {
        long res = 0;
        for (int i = start; i < end; i++) {
            final int digit = Hex.decodeNibble(str.charAt(i));
            if (digit < 0 || digit >= radix) {
                throw new NumberFormatException("Invalid number in SID: " + str);
            }
            res = res * radix + digit;
        }
        return res;
    }

    /**
     * Checks whether this SID matches the given raw 6-byte identifier authority and single 32-bit sub-authority
     * without cloning internal byte arrays.
     *
     * @param authorityHigh16 high 16 bits of the 48-bit identifier authority.
     * @param authorityLow32 low 32 bits of the 48-bit identifier authority.
     * @param subAuthority0 the single 32-bit sub-authority value.
     * @return true if this SID has 1 sub-authority and matches.
     */
    public boolean matchesSingleSubAuthority(
            final int authorityHigh16,
            final int authorityLow32,
            final int subAuthority0) {
        if (identifierAuthority == null || subAuthorities.size() != 1) {
            return false;
        }
        final int hi = ((identifierAuthority[0] & 0xFF) << 8) | (identifierAuthority[1] & 0xFF);
        final int lo = ((identifierAuthority[2] & 0xFF) << 24)
                | ((identifierAuthority[3] & 0xFF) << 16)
                | ((identifierAuthority[4] & 0xFF) << 8)
                | (identifierAuthority[5] & 0xFF);
        if (hi != authorityHigh16 || lo != authorityLow32) {
            return false;
        }
        final byte[] sub = subAuthorities.get(0);
        final int subVal = ((sub[0] & 0xFF) << 24)
                | ((sub[1] & 0xFF) << 16)
                | ((sub[2] & 0xFF) << 8)
                | (sub[3] & 0xFF);
        return subVal == subAuthority0;
    }

    /**
     * Writes this SID directly into the target ByteBuffer without allocating an intermediate byte[].
     *
     * @param buff target byte buffer.
     */
    void writeTo(final ByteBuffer buff) {
        buff.put(revision);
        buff.put((byte) (subAuthorities.size() & 0xFF));
        if (identifierAuthority != null) {
            buff.put(identifierAuthority);
        } else {
            buff.putShort((short) 0);
            buff.putInt(0);
        }
        for (int i = 0, n = subAuthorities.size(); i < n; i++) {
            final byte[] sub = subAuthorities.get(i);
            buff.put(sub[3]);
            buff.put(sub[2]);
            buff.put(sub[1]);
            buff.put(sub[0]);
        }
    }

    /**
     * Load the SID from the byte buffer returning the next byte position in the buffer.
     *
     * @param buff source byte buffer.
     * @param start start loading byte position.
     * @return next byte position after this SID.
     */
    int parse(final ByteBuffer buff, final int start) {
        int pos = start;

        revision = buff.get(pos++);
        int subAuthorityCount = buff.get(pos++) & 0xFF;

        identifierAuthority = new byte[6];
        for (int i = 0; i < 6; i++) {
            identifierAuthority[i] = buff.get(pos++);
        }

        subAuthorities.clear();
        for (int j = 0; j < subAuthorityCount; j++) {
            // SubAuthority is stored in little-endian on the wire; store as 4-byte big-endian
            byte b0 = buff.get(pos++);
            byte b1 = buff.get(pos++);
            byte b2 = buff.get(pos++);
            byte b3 = buff.get(pos++);
            subAuthorities.add(new byte[] { b3, b2, b1, b0 });
        }

        return pos;
    }

    /**
     * Load the SID from the buffer returning the last SID segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    int parse(final IntBuffer buff, final int start) {
        int pos = start;

        // Check for a SID (http://msdn.microsoft.com/en-us/library/cc230371.aspx)
        final byte[] sidHeader = NumberFacility.getBytes(buff.get(pos));

        // Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
        // This value MUST be set to 0x01.
        revision = sidHeader[0];

        //SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements 
        //in the SubAuthority array. The maximum number of elements allowed is 15.
        int subAuthorityCount = NumberFacility.getInt(sidHeader[1]);

        // IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the 
        // authority under which the SID was created. It describes the entity that created the SID. 
        // The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
        identifierAuthority = new byte[6];

        System.arraycopy(sidHeader, 2, identifierAuthority, 0, 2);

        pos++;
        System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, identifierAuthority, 2, 4);

        // SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely 
        // identifies a principal relative to the IdentifierAuthority. Its length is determined by 
        // SubAuthorityCount.
        subAuthorities.clear();
        for (int j = 0; j < subAuthorityCount; j++) {
            pos++;
            subAuthorities.add(Hex.reverse(NumberFacility.getBytes(buff.get(pos))));
        }

        return pos;
    }

    /**
     * Gets revision level of the SID.
     *
     * @return revision.
     */
    public byte getRevision() {
        return revision;
    }

    /**
     * Gets sub-authority number: an 8-bit unsigned integer that specifies the number of elements in the SubAuthority
     * array. The maximum number of elements allowed is 15.
     *
     * @return sub-authorities number.
     */
    public int getSubAuthorityCount() {
        return subAuthorities == null ? 0 : subAuthorities.size() > 15 ? 15 : subAuthorities.size();
    }

    /**
     * Gets identifier authority: 6 bytes describing the entity that created the SID.
     *
     * @return identifier authority.
     */
    public byte[] getIdentifierAuthority() {
        return identifierAuthority == null ? null : Arrays.copyOf(identifierAuthority, identifierAuthority.length);
    }

    /**
     * Gets sub-authorities: a list of unsigned 32-bit integers that uniquely identifies a principal
     * relative to the IdentifierAuthority.
     *
     * @return sub-authorities.
     */
    public List<byte[]> getSubAuthorities() {
        final List<byte[]> res = new ArrayList<>(getSubAuthorityCount());
        for (byte[] sub : subAuthorities) {
            if (sub != null) {
                res.add(Arrays.copyOf(sub, sub.length));
            }
        }
        return Collections.unmodifiableList(res);
    }

    /**
     * Gets size of the SID byte array form.
     *
     * @return size of SID byte aray form.
     */
    public int getSize() {
        return 8 + subAuthorities.size() * 4;
    }

    /**
     * Sets revision level of the SID.
     *
     * @param revision revision.
     * @return the current SID instance.
     */
    public SID setRevision(byte revision) {
        this.revision = revision;
        return this;
    }

    /**
     * Sets idetifier authority: 6 bytes describing the entity that created the SID.
     *
     * @param identifierAuthority identifier authority.
     * @return the current SID instance.
     */
    public SID setIdentifierAuthority(byte[] identifierAuthority) {
        if (identifierAuthority == null || identifierAuthority.length != 6) {
            throw new IllegalArgumentException("Invalid identifier authority");
        }

        this.identifierAuthority = Arrays.copyOf(identifierAuthority, identifierAuthority.length);
        return this;
    }

    /**
     * Adds sub-authority: a principal relative to the IdentifierAuthority.
     *
     * @param sub sub-authority as 4-byte big-endian array.
     * @return the current SID instance.
     */
    public SID addSubAuthority(byte[] sub) {
        if (sub == null || sub.length != 4) {
            throw new IllegalArgumentException("Invalid sub-authority to be added");
        }

        this.subAuthorities.add(Arrays.copyOf(sub, sub.length));
        return this;
    }

    /**
     * Adds a 32-bit unsigned sub-authority value (RID).
     *
     * @param subAuthority 32-bit sub-authority value.
     * @return the current SID instance.
     */
    public SID addSubAuthority(final long subAuthority) {
        this.subAuthorities.add(NumberFacility.getUIntBytes(subAuthority));
        return this;
    }

    /**
     * Serializes to byte array.
     *
     * @return serialized SID.
     */
    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(getSize());
        writeTo(buff);
        return buff.array();
    }

    /**
     * Serializes to string.
     *
     * @return serialized SID.
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();
        bld.append("S-").append(revision & 0xFF).append('-');

        if (identifierAuthority != null) {
            if (identifierAuthority[0] == 0x00 && identifierAuthority[1] == 0x00) {
                bld.append(NumberFacility.getUInt(
                        identifierAuthority[2], identifierAuthority[3], identifierAuthority[4], identifierAuthority[5]));
            } else {
                bld.append(Hex.get(identifierAuthority));
            }
        } else {
            bld.append('0');
        }

        if (subAuthorities.isEmpty()) {
            bld.append("-0");
        } else {
            for (byte[] sub : subAuthorities) {
                bld.append('-');
                bld.append(NumberFacility.getUInt(sub));
            }
        }

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     *
     * @param sid SID to be compared with.
     * @return <tt>true</tt> if equals; <tt>false</tt> otherwise.
     */
    @Override
    public boolean equals(final Object sid) {
        if (this == sid) {
            return true;
        }
        if (!(sid instanceof SID)) {
            return false;
        }

        final SID ext = (SID) sid;

        if (revision != ext.revision) {
            LOG.debug("Different revision");
            return false;
        }

        if (subAuthorities.size() != ext.subAuthorities.size()) {
            LOG.debug("Different sub authorities");
            return false;
        }

        if (!Arrays.equals(identifierAuthority, ext.identifierAuthority)) {
            LOG.debug("Different identifier authority: {}-{}",
                    Hex.get(identifierAuthority), Hex.get(ext.identifierAuthority));
            return false;
        }

        for (int i = 0; i < subAuthorities.size(); i++) {
            if (!Arrays.equals(subAuthorities.get(i), ext.subAuthorities.get(i))) {
                LOG.debug("Different sub authority: {}-{}",
                        Hex.get(subAuthorities.get(i)), Hex.get(ext.subAuthorities.get(i)));
                return false;
            }
        }

        return true;
    }

    /**
     * {@inheritDoc }
     *
     * @return hashcode.
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + this.revision;
        hash = 97 * hash + Arrays.hashCode(this.identifierAuthority);
        for (byte[] sub : this.subAuthorities) {
            hash = 97 * hash + Arrays.hashCode(sub);
        }
        return hash;
    }

}

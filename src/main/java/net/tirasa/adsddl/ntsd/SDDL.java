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
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.data.SddlControlFlag;
import net.tirasa.adsddl.ntsd.utils.AdsddlLogger;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;

/**
 * The SECURITY_DESCRIPTOR structure defines the security attributes of an object. These attributes specify who owns the
 * object; who can access the object and what they can do with it; what level of audit logging should be applied to the
 * object; and what kind of restrictions apply to the use of the security descriptor.
 *
 * Security descriptors appear in one of two forms, absolute or self-relative.
 *
 * A security descriptor is said to be in absolute format if it stores all of its security information via pointer
 * fields, as specified in the RPC representation in section 2.4.6.1.
 *
 * A security descriptor is said to be in self-relative format if it stores all of its security information in a
 * contiguous block of memory and expresses all of its pointer fields as offsets from its beginning. The order of
 * appearance of pointer target fields is not required to be in any particular order; locating the OwnerSid, GroupSid,
 * Sacl, and/or Dacl should only be based on OffsetOwner, OffsetGroup, OffsetSacl, and/or OffsetDacl pointers found in
 * the fixed portion of the relative security descriptor.<br>
 *
 * The self-relative form of the security descriptor is required if one wants to transmit the SECURITY_DESCRIPTOR
 * structure as an opaque data structure for transmission in communication protocols over a wire, or for storage on
 * secondary media; the absolute form cannot be transmitted because it contains pointers to objects that are generally
 * not accessible to the recipient.
 *
 * When a self-relative security descriptor is transmitted over a wire, it is sent in little-endian format and requires
 * no padding.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230366.aspx" target="_top">cc230366</a>
 */
public class SDDL {

    /**
     * Logger.
     */
    protected static final AdsddlLogger LOG = AdsddlLogger.getLogger(SDDL.class);

    /**
     * An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure.
     * This field MUST be set to one.
     */
    private byte revision;

    /**
     * An unsigned 16-bit field that specifies control access bit flags. The Self Relative (SR) bit MUST be set when the
     * security descriptor is in self-relative format.
     */
    private byte[] controlFlags;

    /**
     * An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the owner of the object to
     * which the security descriptor is associated. This must be a valid offset if the OD flag is not set. If this field
     * is set to zero, the OwnerSid field MUST not be present.
     */
    private long offsetOwner;

    /**
     * An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the group of the object to
     * which the security descriptor is associated. This must be a valid offset if the GD flag is not set. If this field
     * is set to zero, the GroupSid field MUST not be present.
     */
    private long offsetGroup;

    /**
     * An unsigned 32-bit integer that specifies the offset to the ACL that contains system ACEs. Typically, the system
     * ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, or
     * SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE. This must be a valid offset if the SP flag is set;
     * if the SP flag is not set, this field MUST be set to zero. If this field is set to zero, the Sacl field MUST not
     * be present.
     */
    private long offsetSACL;

    /**
     * An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs that control access.
     * Typically, the DACL contains ACEs that grant or deny access to principals or groups. This must be a valid offset
     * if the DP flag is set; if the DP flag is not set, this field MUST be set to zero. If this field is set to zero,
     * the Dacl field MUST not be present.
     */
    private long offsetDACL;

    /**
     * The SID of the owner of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
     * the OffsetOwner field is not zero.
     */
    private SID owner;

    /**
     * The SID of the group of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
     * the GroupOwner field is not zero.
     */
    private SID group;

    /**
     * The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the SP flag
     * is set.
     */
    private ACL dacl;

    /**
     * The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the DP flag
     * is set.
     */
    private ACL sacl;

    /**
     * Default constructor creating an empty self-relative SECURITY_DESCRIPTOR with revision 1.
     */
    public SDDL() {
        this.revision = 0x01;
        this.controlFlags = SddlControlFlag.toBytes(SddlControlFlag.SE_SELF_RELATIVE.getValue());
    }

    /**
     * Constructor.
     *
     * @param src source as byte array.
     */
    public SDDL(byte[] src) {
        final ByteBuffer sddlBuffer = ByteBuffer.wrap(src);
        parse(sddlBuffer, 0);
    }

    /**
     * Load the SDDL from the byte buffer returning the last SDDL segment position in the buffer.
     *
     * @param buff source byte buffer.
     * @param start start loading byte position.
     * @return last loading position.
     */
    private int parse(final ByteBuffer buff, final int start) {
        int pos = start;

        /**
         * Revision (1 byte): An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR
         * structure. This field MUST be set to one.
         */
        revision = buff.get(pos);

        /**
         * Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative
         * (SR) bit MUST be set when the security descriptor is in self-relative format.
         */
        controlFlags = new byte[] { buff.get(pos + 3), buff.get(pos + 2) };
        final boolean[] controlFlag = NumberFacility.getBits(controlFlags);

        pos += 4;
        /**
         * OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
         * specifies the owner of the object to which the security descriptor is associated. This must be a valid
         * offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
         */
        if (!controlFlag[15]) {
            offsetOwner = readUInt32LE(buff, pos);
        } else {
            offsetOwner = 0;
        }

        pos += 4;

        /**
         * OffsetGroup (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
         * specifies the group of the object to which the security descriptor is associated. This must be a valid
         * offset if the GD flag is not set. If this field is set to zero, the GroupSid field MUST not be present.
         */
        if (!controlFlag[14]) {
            offsetGroup = readUInt32LE(buff, pos);
        } else {
            offsetGroup = 0;
        }

        pos += 4;

        /**
         * OffsetSacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains
         * system ACEs. Typically, the system ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE,
         * SYSTEM_AUDIT_CALLBACK_ACE, or SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE (as specified
         * in section 2.4.4.13). This must be a valid offset if the SP flag is set; if the SP flag is not set, this
         * field MUST be set to zero. If this field is set to zero, the Sacl field MUST not be present.
         */
        if (controlFlag[11]) {
            offsetSACL = readUInt32LE(buff, pos);
        } else {
            offsetSACL = 0;
        }

        pos += 4;

        /**
         * OffsetDacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs
         * that control access. Typically, the DACL contains ACEs that grant or deny access to principals or groups.
         * This must be a valid offset if the DP flag is set; if the DP flag is not set, this field MUST be set to
         * zero. If this field is set to zero, the Dacl field MUST not be present.
         */
        if (controlFlag[13]) {
            offsetDACL = readUInt32LE(buff, pos);
        } else {
            offsetDACL = 0;
        }

        /**
         * OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the OffsetOwner field is not zero.
         */
        if (offsetOwner > 0) {
            owner = new SID();
            pos = owner.parse(buff, (int) offsetOwner);
        }

        /**
         * GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the GroupOwner field is not zero.
         */
        if (offsetGroup > 0) {
            group = new SID();
            pos = group.parse(buff, (int) offsetGroup);
        }

        /**
         * Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the SP flag is set.
         */
        if (offsetSACL > 0) {
            sacl = new ACL();
            pos = sacl.parse(buff, (int) offsetSACL);
        }

        /**
         * Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the DP flag is set.
         */
        if (offsetDACL > 0) {
            dacl = new ACL();
            pos = dacl.parse(buff, (int) offsetDACL);
        }

        return pos;
    }

    private static long readUInt32LE(final ByteBuffer buff, final int pos) {
        return ((buff.get(pos) & 0xFFL))
                | ((buff.get(pos + 1) & 0xFFL) << 8)
                | ((buff.get(pos + 2) & 0xFFL) << 16)
                | ((buff.get(pos + 3) & 0xFFL) << 24);
    }

    /**
     * Gets size in terms of number of bytes.
     *
     * @return size.
     */
    public int getSize() {
        return 20 + (sacl == null ? 0 : sacl.getSize())
                + (dacl == null ? 0 : dacl.getSize())
                + (owner == null ? 0 : owner.getSize())
                + (group == null ? 0 : group.getSize());
    }

    /**
     * Get revison.
     *
     * @return An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure..
     */
    public byte getRevision() {
        return revision;
    }

    /**
     * Sets revision of the SECURITY_DESCRIPTOR structure (must be 0x01).
     *
     * @param revision revision byte.
     * @return the current SDDL instance.
     */
    public SDDL setRevision(final byte revision) {
        this.revision = revision;
        return this;
    }

    /**
     * Gets control.
     *
     * @return An unsigned 16-bit field that specifies control access bit flags.
     */
    public byte[] getControlFlags() {
        return controlFlags;
    }

    /**
     * Sets raw 2-byte control flags (high byte at index 0, low byte at index 1).
     *
     * @param controlFlags 2-byte control flags array.
     * @return the current SDDL instance.
     */
    public SDDL setControlFlags(final byte[] controlFlags) {
        if (controlFlags == null || controlFlags.length != 2) {
            throw new IllegalArgumentException("Control flags must be a 2-byte array");
        }
        this.controlFlags = Arrays.copyOf(controlFlags, 2);
        return this;
    }

    /**
     * Gets parsed control flags as a list of {@link SddlControlFlag}.
     *
     * @return active control flags.
     */
    public List<SddlControlFlag> getParsedControlFlags() {
        return SddlControlFlag.parseValue(controlFlags);
    }

    /**
     * Checks whether a specific {@link SddlControlFlag} is set.
     *
     * @param flag control flag to check.
     * @return true if set.
     */
    public boolean hasControlFlag(final SddlControlFlag flag) {
        if (flag == null || controlFlags == null || controlFlags.length < 2) {
            return false;
        }
        final int mask = ((controlFlags[0] & 0xFF) << 8) | (controlFlags[1] & 0xFF);
        return (mask & flag.getValue()) == flag.getValue();
    }

    /**
     * Adds one or more {@link SddlControlFlag} bits to this security descriptor.
     *
     * @param flags flags to set.
     * @return the current SDDL instance.
     */
    public SDDL addControlFlags(final SddlControlFlag... flags) {
        int mask = (controlFlags == null || controlFlags.length < 2)
                ? SddlControlFlag.SE_SELF_RELATIVE.getValue()
                : (((controlFlags[0] & 0xFF) << 8) | (controlFlags[1] & 0xFF));
        for (SddlControlFlag flag : flags) {
            if (flag != null) {
                mask |= flag.getValue();
            }
        }
        this.controlFlags = SddlControlFlag.toBytes(mask);
        return this;
    }

    /**
     * Removes one or more {@link SddlControlFlag} bits from this security descriptor.
     *
     * @param flags flags to clear.
     * @return the current SDDL instance.
     */
    public SDDL removeControlFlags(final SddlControlFlag... flags) {
        if (controlFlags == null || controlFlags.length < 2) {
            return this;
        }
        int mask = ((controlFlags[0] & 0xFF) << 8) | (controlFlags[1] & 0xFF);
        for (SddlControlFlag flag : flags) {
            if (flag != null) {
                mask &= ~flag.getValue();
            }
        }
        this.controlFlags = SddlControlFlag.toBytes(mask);
        return this;
    }

    /**
     * Gets owner.
     *
     * @return The SID of the owner of the object.
     */
    public SID getOwner() {
        return owner;
    }

    /**
     * Sets owner SID.
     *
     * @param owner owner SID.
     * @return the current SDDL instance.
     */
    public SDDL setOwner(final SID owner) {
        this.owner = owner;
        return this;
    }

    /**
     * Gets group.
     *
     * @return The SID of the group of the object.
     */
    public SID getGroup() {
        return group;
    }

    /**
     * Sets group SID.
     *
     * @param group group SID.
     * @return the current SDDL instance.
     */
    public SDDL setGroup(final SID group) {
        this.group = group;
        return this;
    }

    /**
     * Gets DACL.
     *
     * @return The DACL of the object.
     */
    public ACL getDacl() {
        return dacl;
    }

    /**
     * Sets DACL and updates the {@link SddlControlFlag#SE_DACL_PRESENT} control flag.
     *
     * @param dacl DACL.
     * @return the current SDDL instance.
     */
    public SDDL setDacl(final ACL dacl) {
        this.dacl = dacl;
        if (dacl != null) {
            addControlFlags(SddlControlFlag.SE_DACL_PRESENT);
        } else {
            removeControlFlags(SddlControlFlag.SE_DACL_PRESENT);
        }
        return this;
    }

    /**
     * Gets SACL.
     *
     * @return The SACL of the object.
     */
    public ACL getSacl() {
        return sacl;
    }

    /**
     * Sets SACL and updates the {@link SddlControlFlag#SE_SACL_PRESENT} control flag.
     *
     * @param sacl SACL.
     * @return the current SDDL instance.
     */
    public SDDL setSacl(final ACL sacl) {
        this.sacl = sacl;
        if (sacl != null) {
            addControlFlags(SddlControlFlag.SE_SACL_PRESENT);
        } else {
            removeControlFlags(SddlControlFlag.SE_SACL_PRESENT);
        }
        return this;
    }

    /**
     * Serializes SDDL as byte array using a single contiguous ByteBuffer without intermediate byte[] allocations.
     * Automatically ensures {@link SddlControlFlag#SE_SELF_RELATIVE}, {@link SddlControlFlag#SE_DACL_PRESENT},
     * and {@link SddlControlFlag#SE_SACL_PRESENT} match the actual presence of DACL and SACL.
     *
     * @return SDDL as byte array.
     */
    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(getSize()).order(ByteOrder.LITTLE_ENDIAN);

        // add revision & reserved
        buff.put(revision == 0 ? (byte) 0x01 : revision);
        buff.put((byte) 0x00);

        // synchronize control flags with actual presence of SACL/DACL
        int ctrlMask = (controlFlags == null || controlFlags.length < 2)
                ? SddlControlFlag.SE_SELF_RELATIVE.getValue()
                : (((controlFlags[0] & 0xFF) << 8) | (controlFlags[1] & 0xFF));
        ctrlMask |= SddlControlFlag.SE_SELF_RELATIVE.getValue();
        if (dacl != null) {
            ctrlMask |= SddlControlFlag.SE_DACL_PRESENT.getValue();
        }
        if (sacl != null) {
            ctrlMask |= SddlControlFlag.SE_SACL_PRESENT.getValue();
        }
        buff.putShort((short) ctrlMask);

        int nextAvailablePosition = 20;

        // add owner SID
        buff.putInt(4, owner == null ? 0 : nextAvailablePosition);
        if (owner != null) {
            buff.position(nextAvailablePosition);
            owner.writeTo(buff);
            nextAvailablePosition = buff.position();
        }

        // add group SID
        buff.putInt(8, group == null ? 0 : nextAvailablePosition);
        if (group != null) {
            buff.position(nextAvailablePosition);
            group.writeTo(buff);
            nextAvailablePosition = buff.position();
        }

        // add SACL
        buff.putInt(12, sacl == null ? 0 : nextAvailablePosition);
        if (sacl != null) {
            buff.position(nextAvailablePosition);
            sacl.writeTo(buff);
            nextAvailablePosition = buff.position();
        }

        // add DACL
        buff.putInt(16, dacl == null ? 0 : nextAvailablePosition);
        if (dacl != null) {
            buff.position(nextAvailablePosition);
            dacl.writeTo(buff);
        }

        return buff.array();
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SDDL)) {
            return false;
        }

        final SDDL ext = (SDDL) o;

        if (revision != ext.revision) {
            LOG.debug("Different revision");
            return false;
        }

        if (getSize() != ext.getSize()) {
            LOG.debug("Different size");
            return false;
        }

        if (!Arrays.equals(getControlFlags(), ext.getControlFlags())) {
            LOG.debug("Different control flags");
            return false;
        }

        if (!Objects.equals(getOwner(), ext.getOwner())) {
            LOG.debug("Different owner ....\nExpected: {}\nActual: {}",
                    getOwner(), ext.getOwner());
            return false;
        }

        if (!Objects.equals(getGroup(), ext.getGroup())) {
            LOG.debug("Different group ....\nExpected: {}\nActual: {}",
                    getGroup(), ext.getGroup());
            return false;
        }

        if (!Objects.equals(getDacl(), ext.getDacl())) {
            LOG.debug("Different dacl");
            return false;
        }

        if (!Objects.equals(getSacl(), ext.getSacl())) {
            LOG.debug("Different sacl");
            return false;
        }
        return true;
    }

    /**
     * Serializes SDDL as string.
     *
     * @return SDDL string representation.
     *
     * @see <a href="https://msdn.microsoft.com/en-us/library/hh877835.aspx" target="_top">hh877835</a>
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();

        if (owner != null) {
            bld.append("O:");
            bld.append(owner.toString());
        }
        if (group != null) {
            bld.append("G:");
            bld.append(group.toString());
        }

        if (dacl != null) {
            bld.append("D:");
            bld.append(dacl.toString());
        }

        if (sacl != null) {
            bld.append("S:");
            bld.append(sacl.toString());
        }

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + this.revision;
        hash = 71 * hash + Arrays.hashCode(this.controlFlags);
        hash = 71 * hash + Objects.hashCode(this.owner);
        hash = 71 * hash + Objects.hashCode(this.group);
        hash = 71 * hash + Objects.hashCode(this.dacl);
        hash = 71 * hash + Objects.hashCode(this.sacl);
        return hash;
    }
}

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
package net.tirasa.adsddl.ntsd.data;

import java.util.ArrayList;
import java.util.List;

/**
 * An unsigned 16-bit field that specifies control access bit flags of a SECURITY_DESCRIPTOR structure
 * ([MS-DTYP] section 2.4.6).
 */
public enum SddlControlFlag {

    /**
     * 0x0001 (OD) - Owner Defaulted: Indicates that the SID of the owner of the security descriptor was provided
     * by a defaulting mechanism.
     */
    SE_OWNER_DEFAULTED(0x0001, "OD"),
    /**
     * 0x0002 (GD) - Group Defaulted: Indicates that the SID of the security descriptor group was provided by a
     * defaulting mechanism.
     */
    SE_GROUP_DEFAULTED(0x0002, "GD"),
    /**
     * 0x0004 (DP) - DACL Present: Indicates a security descriptor that has a DACL.
     */
    SE_DACL_PRESENT(0x0004, "DP"),
    /**
     * 0x0008 (DD) - DACL Defaulted: Indicates a security descriptor with a default DACL.
     */
    SE_DACL_DEFAULTED(0x0008, "DD"),
    /**
     * 0x0010 (SP) - SACL Present: Indicates a security descriptor that has a SACL.
     */
    SE_SACL_PRESENT(0x0010, "SP"),
    /**
     * 0x0020 (SD) - SACL Defaulted: Indicates that the SACL was provided by a defaulting mechanism.
     */
    SE_SACL_DEFAULTED(0x0020, "SD"),
    /**
     * 0x0040 (SS) - Server Security.
     */
    SE_SERVER_SECURITY(0x0040, "SS"),
    /**
     * 0x0080 (DT) - DACL Trusted.
     */
    SE_DACL_TRUSTED(0x0080, "DT"),
    /**
     * 0x0100 (DC) - DACL Computation Required (SE_DACL_AUTO_INHERIT_REQ): Indicates a required security descriptor
     * in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable
     * access control entries (ACEs) to existing child objects.
     */
    SE_DACL_AUTO_INHERIT_REQ(0x0100, "DC"),
    /**
     * 0x0200 (SC) - SACL Computation Required (SE_SACL_AUTO_INHERIT_REQ): Indicates a required security descriptor
     * in which the system access control list (SACL) is set up to support automatic propagation of inheritable
     * ACEs to existing child objects.
     */
    SE_SACL_AUTO_INHERIT_REQ(0x0200, "SC"),
    /**
     * 0x0400 (DI) - DACL Auto-Inherited: Indicates a security descriptor in which the DACL is set up to support
     * automatic propagation of inheritable ACEs to existing child objects.
     */
    SE_DACL_AUTO_INHERITED(0x0400, "DI"),
    /**
     * 0x0800 (SI) - SACL Auto-Inherited: Indicates a security descriptor in which the SACL is set up to support
     * automatic propagation of inheritable ACEs to existing child objects.
     */
    SE_SACL_AUTO_INHERITED(0x0800, "SI"),
    /**
     * 0x1000 (PD) - DACL Protected: Prevents the DACL of the security descriptor from being modified by inheritable
     * ACEs.
     */
    SE_DACL_PROTECTED(0x1000, "PD"),
    /**
     * 0x2000 (PS) - SACL Protected: Prevents the SACL of the security descriptor from being modified by inheritable
     * ACEs.
     */
    SE_SACL_PROTECTED(0x2000, "PS"),
    /**
     * 0x4000 (RM) - RM Control Valid: Indicates that the resource manager control is valid.
     */
    SE_RM_CONTROL_VALID(0x4000, "RM"),
    /**
     * 0x8000 (SR) - Self-Relative: Indicates a self-relative security descriptor.
     */
    SE_SELF_RELATIVE(0x8000, "SR");

    private static final SddlControlFlag[] BY_BIT = new SddlControlFlag[16];

    static {
        for (SddlControlFlag flag : SddlControlFlag.values()) {
            BY_BIT[Integer.numberOfTrailingZeros(flag.value)] = flag;
        }
    }

    private final int value;

    private final String code;

    SddlControlFlag(final int value, final String code) {
        this.value = value;
        this.code = code;
    }

    /**
     * Gets the 16-bit integer flag mask.
     *
     * @return flag bitmask.
     */
    public int getValue() {
        return value;
    }

    /**
     * Gets two-letter flag code.
     *
     * @return two-letter code.
     */
    public String getCode() {
        return code;
    }

    @Override
    public String toString() {
        return code;
    }

    /**
     * Parses a 16-bit control mask into a list of SddlControlFlags.
     *
     * @param mask 16-bit control mask.
     * @return list of active control flags.
     */
    public static List<SddlControlFlag> parseValue(final int mask) {
        int bits = mask & 0xFFFF;
        final List<SddlControlFlag> res = new ArrayList<>(Integer.bitCount(bits));
        while (bits != 0) {
            final int lowestBit = bits & -bits;
            final SddlControlFlag flag = BY_BIT[Integer.numberOfTrailingZeros(lowestBit)];
            if (flag != null) {
                res.add(flag);
            }
            bits ^= lowestBit;
        }
        return res;
    }

    /**
     * Parses a 2-byte big-endian controlFlags array (as returned by {@code SDDL.getControlFlags()}) into a list of
     * SddlControlFlags.
     *
     * @param controlFlags 2-byte control flags array (high byte at index 0, low byte at index 1).
     * @return list of active control flags.
     */
    public static List<SddlControlFlag> parseValue(final byte[] controlFlags) {
        if (controlFlags == null || controlFlags.length < 2) {
            return new ArrayList<>(0);
        }
        final int mask = ((controlFlags[0] & 0xFF) << 8) | (controlFlags[1] & 0xFF);
        return parseValue(mask);
    }

    /**
     * Converts a 16-bit control mask to a 2-byte big-endian array (high byte at index 0, low byte at index 1).
     *
     * @param mask 16-bit control mask.
     * @return 2-byte control flags array.
     */
    public static byte[] toBytes(final int mask) {
        return new byte[] { (byte) ((mask >>> 8) & 0xFF), (byte) (mask & 0xFF) };
    }
}

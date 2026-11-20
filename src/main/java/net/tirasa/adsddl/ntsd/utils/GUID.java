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
/*
 * Modified by Jan Hladěna (2026) - zero-allocation GUID formatting, decoding, and comparison.
 */
package net.tirasa.adsddl.ntsd.utils;

/**
 * Utility class to manage GUID.
 * A GUID, also known as a UUID, is a 16-byte structure, intended to serve as a unique identifier for an object. There
 * are three representations of a GUID, as described in the following sections.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230326.aspx" target="_top">cc230326</a>
 */
public class GUID {

    private static final char[] HEX_LOWER = "0123456789abcdef".toCharArray();

    /**
     * Gets GUID as string.
     *
     * @param GUID GUID.
     * @return GUID as string.
     */
    public static String getGuidAsString(byte[] GUID) {
        if (GUID == null || GUID.length < 16) {
            throw new IllegalArgumentException("GUID must be 16 bytes");
        }
        final char[] chars = new char[36];
        writeHexByte(chars, 0, GUID[3]);
        writeHexByte(chars, 2, GUID[2]);
        writeHexByte(chars, 4, GUID[1]);
        writeHexByte(chars, 6, GUID[0]);
        chars[8] = '-';
        writeHexByte(chars, 9, GUID[5]);
        writeHexByte(chars, 11, GUID[4]);
        chars[13] = '-';
        writeHexByte(chars, 14, GUID[7]);
        writeHexByte(chars, 16, GUID[6]);
        chars[18] = '-';
        writeHexByte(chars, 19, GUID[8]);
        writeHexByte(chars, 21, GUID[9]);
        chars[23] = '-';
        writeHexByte(chars, 24, GUID[10]);
        writeHexByte(chars, 26, GUID[11]);
        writeHexByte(chars, 28, GUID[12]);
        writeHexByte(chars, 30, GUID[13]);
        writeHexByte(chars, 32, GUID[14]);
        writeHexByte(chars, 34, GUID[15]);

        return new String(chars);
    }

    /**
     * Gets GUID as byte array directly from a 36-char GUID string without intermediate UUID/ByteBuffer allocations.
     *
     * @param GUID GUID string in form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
     * @return GUID as 16-byte array in mixed-endian AD wire format.
     */
    public static byte[] getGuidAsByteArray(final String GUID) {
        if (GUID == null || GUID.length() != 36
                || GUID.charAt(8) != '-' || GUID.charAt(13) != '-'
                || GUID.charAt(18) != '-' || GUID.charAt(23) != '-') {
            throw new IllegalArgumentException("Invalid GUID string: " + GUID);
        }

        return new byte[] {
            // Data1 (4 bytes, little-endian)
            Hex.decodeByte(GUID, 6),
            Hex.decodeByte(GUID, 4),
            Hex.decodeByte(GUID, 2),
            Hex.decodeByte(GUID, 0),
            // Data2 (2 bytes, little-endian)
            Hex.decodeByte(GUID, 11),
            Hex.decodeByte(GUID, 9),
            // Data3 (2 bytes, little-endian)
            Hex.decodeByte(GUID, 16),
            Hex.decodeByte(GUID, 14),
            // Data4 (8 bytes, big-endian)
            Hex.decodeByte(GUID, 19),
            Hex.decodeByte(GUID, 21),
            Hex.decodeByte(GUID, 24),
            Hex.decodeByte(GUID, 26),
            Hex.decodeByte(GUID, 28),
            Hex.decodeByte(GUID, 30),
            Hex.decodeByte(GUID, 32),
            Hex.decodeByte(GUID, 34)
        };
    }

    /**
     * Compares a 16-byte binary GUID with a 36-char string GUID without allocating a String or byte[].
     *
     * @param guidBytes 16-byte binary GUID.
     * @param guidStr 36-char string GUID.
     * @return true if they represent the same GUID.
     */
    public static boolean equals(final byte[] guidBytes, final String guidStr) {
        if (guidBytes == null || guidBytes.length != 16 || guidStr == null || guidStr.length() != 36) {
            return false;
        }
        if (guidStr.charAt(8) != '-' || guidStr.charAt(13) != '-'
                || guidStr.charAt(18) != '-' || guidStr.charAt(23) != '-') {
            return false;
        }
        return matchHexByte(guidBytes[3], guidStr, 0)
                && matchHexByte(guidBytes[2], guidStr, 2)
                && matchHexByte(guidBytes[1], guidStr, 4)
                && matchHexByte(guidBytes[0], guidStr, 6)
                && matchHexByte(guidBytes[5], guidStr, 9)
                && matchHexByte(guidBytes[4], guidStr, 11)
                && matchHexByte(guidBytes[7], guidStr, 14)
                && matchHexByte(guidBytes[6], guidStr, 16)
                && matchHexByte(guidBytes[8], guidStr, 19)
                && matchHexByte(guidBytes[9], guidStr, 21)
                && matchHexByte(guidBytes[10], guidStr, 24)
                && matchHexByte(guidBytes[11], guidStr, 26)
                && matchHexByte(guidBytes[12], guidStr, 28)
                && matchHexByte(guidBytes[13], guidStr, 30)
                && matchHexByte(guidBytes[14], guidStr, 32)
                && matchHexByte(guidBytes[15], guidStr, 34);
    }

    private static boolean matchHexByte(final byte b, final String str, final int offset) {
        final int hi = Hex.decodeNibble(str.charAt(offset));
        final int lo = Hex.decodeNibble(str.charAt(offset + 1));
        return ((hi | lo) >= 0) && (((hi << 4) | lo) == (b & 0xFF));
    }

    private static void writeHexByte(final char[] dst, final int offset, final byte b) {
        final int v = b & 0xFF;
        dst[offset] = HEX_LOWER[v >>> 4];
        dst[offset + 1] = HEX_LOWER[v & 0x0F];
    }
}

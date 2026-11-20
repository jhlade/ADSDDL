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
 * Modified by Jan Hladěna (2026) - lookup-table hex encoding and nibble decoding.
 */
package net.tirasa.adsddl.ntsd.utils;

/**
 * Utility class to be used to convert byte arrays into hexadecimal strings.
 */
public class Hex {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Gets hex string corresponding to the given byte array from "{@code from}" position to "{@code to}".
     *
     * @param bytes bytes.
     * @param from from position.
     * @param to to position.
     * @return hex string.
     */
    public static String get(byte[] bytes, int from, int to) {
        if (bytes == null || from >= to) {
            return "";
        }
        final int len = to - from;
        final char[] hexChars = new char[len << 1];
        for (int i = 0; i < len; i++) {
            final int v = bytes[from + i] & 0xFF;
            final int idx = i << 1;
            hexChars[idx] = HEX_ARRAY[v >>> 4];
            hexChars[idx | 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Gets hex string corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return hex string.
     */
    public static String get(byte... bytes) {
        return bytes == null ? "" : get(bytes, 0, bytes.length);
    }

    /**
     * Gets escaped hex string corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return escaped hex string
     */
    public static String getEscaped(byte... bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        final char[] hexChars = new char[bytes.length * 3];
        for (int i = 0, idx = 0; i < bytes.length; i++, idx += 3) {
            final int v = bytes[i] & 0xFF;
            hexChars[idx] = '\\';
            hexChars[idx + 1] = HEX_ARRAY[v >>> 4];
            hexChars[idx + 2] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Gets hex string corresponding to the given byte.
     *
     * @param b byte.
     * @return hex string.
     */
    public static String get(byte b) {
        final int v = b & 0xFF;
        return new String(new char[] { HEX_ARRAY[v >>> 4], HEX_ARRAY[v & 0x0F] });
    }

    /**
     * Decodes a single hex character into its 4-bit nibble value, or -1 if invalid.
     *
     * @param c hex character.
     * @return 0..15, or -1 if not a valid hex character.
     */
    public static int decodeNibble(final char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /**
     * Decodes a two-character hex byte from a string at the given offset.
     *
     * @param str source string.
     * @param offset character offset.
     * @return decoded byte.
     */
    public static byte decodeByte(final String str, final int offset) {
        final int hi = decodeNibble(str.charAt(offset));
        final int lo = decodeNibble(str.charAt(offset + 1));
        if ((hi | lo) < 0) {
            throw new IllegalArgumentException("Invalid hex byte at offset " + offset + " in: " + str);
        }
        return (byte) ((hi << 4) | lo);
    }

    /**
     * Reverses bytes.
     *
     * @param bytes bytes.
     * @return reversed byte array.
     */
    public static byte[] reverse(byte... bytes) {
        if (bytes == null) {
            return null;
        }
        final int len = bytes.length;
        final byte[] res = new byte[len];
        for (int i = 0, j = len - 1; j >= 0; i++, j--) {
            res[i] = bytes[j];
        }
        return res;
    }
}

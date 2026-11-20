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
package net.tirasa.adsddl.ntsd.utils;

import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Utility class to be used to manipulate byte arrays and numbers.
 */
public class NumberFacility {

    /**
     * Gets byte array corresponding to a given unsigned integer.
     *
     * @param value unsigned integer.
     * @return byte array.
     */
    public static byte[] getUIntBytes(final long value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    /**
     * Gets byte array from integer.
     *
     * @param value integer.
     * @return byte array.
     */
    public static byte[] getBytes(final int value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    /**
     * Gets byte array from integer in big-endian order with the given length.
     *
     * @param value integer.
     * @param length array size.
     * @return byte array.
     */
    public static byte[] getBytes(final int value, final int length) {
        return getBytes((long) value & 0xFFFFFFFFL, length);
    }

    /**
     * Gets byte array from long in big-endian order with the given length.
     *
     * @param value long value.
     * @param length array size.
     * @return byte array.
     */
    public static byte[] getBytes(final long value, final int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative");
        }
        final byte[] res = new byte[length];
        long v = value;
        for (int i = length - 1; i >= 0 && v != 0; i--) {
            res[i] = (byte) (v & 0xFF);
            v >>>= 8;
        }
        return res;
    }

    /**
     * Remove 0x00 bytes from left side.
     *
     * @param bytes source array.
     * @return trimmed array.
     */
    @SuppressWarnings("empty-statement")
    public static byte[] leftTrim(final byte... bytes) {
        int pos = 0;
        for (; pos < bytes.length && bytes[pos] == 0x00; pos++);

        if (pos < bytes.length) {
            return Arrays.copyOfRange(bytes, pos, bytes.length);
        } else {
            return new byte[] { 0x00 };
        }
    }

    /**
     * Remove 0x00 bytes from right side.
     *
     * @param bytes source array.
     * @return trimmed array.
     */
    public static byte[] rightTrim(final byte... bytes) {
        int pos = bytes.length - 1;
        while (pos >= 0 && bytes[pos] == 0x00) {
            pos--;
        }
        return pos >= 0 ? Arrays.copyOf(bytes, pos + 1) : new byte[] { 0x00 };
    }

    /**
     * Gets bits as boolean array from a given byte array.
     *
     * @param bytes bytes.
     * @return bits.
     */
    public static boolean[] getBits(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }

        final boolean[] res = new boolean[bytes.length << 3];

        for (int i = 0; i < bytes.length; i++) {
            final int b = bytes[i] & 0xFF;
            final int base = i << 3;
            res[base] = (b & 0x80) != 0;
            res[base + 1] = (b & 0x40) != 0;
            res[base + 2] = (b & 0x20) != 0;
            res[base + 3] = (b & 0x10) != 0;
            res[base + 4] = (b & 0x08) != 0;
            res[base + 5] = (b & 0x04) != 0;
            res[base + 6] = (b & 0x02) != 0;
            res[base + 7] = (b & 0x01) != 0;
        }

        return res;
    }

    /**
     * Gets bits as boolean array from a given byte.
     *
     * @param b byte.
     * @return bits.
     */
    public static boolean[] getBits(final byte b) {
        final int v = b & 0xFF;
        return new boolean[] {
            (v & 0x80) != 0,
            (v & 0x40) != 0,
            (v & 0x20) != 0,
            (v & 0x10) != 0,
            (v & 0x08) != 0,
            (v & 0x04) != 0,
            (v & 0x02) != 0,
            (v & 0x01) != 0
        };
    }

    /**
     * Reverts bytes and retrieves the corresponding integer value.
     *
     * @param bytes bytes.
     * @return integer.
     */
    public static int getReverseInt(final byte... bytes) {
        return (int) getReverseUInt(bytes);
    }

    /**
     * Reverses bytes and retrieves the corresponding unsigned integer value.
     *
     * @param bytes bytes.
     * @return unsigned integer.
     */
    public static long getReverseUInt(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }
        long res = 0;
        for (int i = bytes.length - 1; i >= 0; i--) {
            res = (res << 8) | (bytes[i] & 0xFFL);
        }
        return res;
    }

    /**
     * Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
     * integer value.
     *
     * @param value integer value.
     * @return reversed integer value.
     */
    public static int getReverseInt(final int value) {
        return Integer.reverseBytes(value);
    }

    /**
     * Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
     * unsigned integer value.
     *
     * @param value integer value.
     * @return reversed unsigned integer value.
     */
    public static long getReverseUInt(final int value) {
        return Integer.reverseBytes(value) & 0xFFFFFFFFL;
    }

    /**
     * Gets integer value corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return integer.
     */
    public static int getInt(final byte... bytes) {
        return (int) getUInt(bytes);
    }

    /**
     * Gets unsigned integer value corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return unsigned integer.
     */
    public static long getUInt(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }

        long res = 0;
        for (int i = 0; i < bytes.length; i++) {
            res = (res << 8) | (bytes[i] & 0xFFL);
        }

        return res;
    }
}

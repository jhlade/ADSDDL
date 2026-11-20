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

import java.nio.ByteBuffer;
import java.util.UUID;

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
     * Gets GUID as byte array.
     *
     * @param GUID GUID.
     * @return GUID as byte array.
     */
    public static byte[] getGuidAsByteArray(final String GUID) {
        final UUID uuid = UUID.fromString(GUID);

        final ByteBuffer buff = ByteBuffer.wrap(new byte[16]);
        buff.putLong(uuid.getMostSignificantBits());
        buff.putLong(uuid.getLeastSignificantBits());

        return new byte[] {
            buff.get(3),
            buff.get(2),
            buff.get(1),
            buff.get(0),
            buff.get(5),
            buff.get(4),
            buff.get(7),
            buff.get(6),
            buff.get(8),
            buff.get(9),
            buff.get(10),
            buff.get(11),
            buff.get(12),
            buff.get(13),
            buff.get(14),
            buff.get(15) };
    }

    private static void writeHexByte(final char[] dst, final int offset, final byte b) {
        int v = b & 0xFF;
        dst[offset] = HEX_LOWER[v >>> 4];
        dst[offset + 1] = HEX_LOWER[v & 0x0F];
    }
}

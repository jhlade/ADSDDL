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

/**
 * Utility class to be used to convert byte arrays into hexadecimal strings.
 */
public class Hex {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Gets hex string corresponding to the given byte array from "<tt>from</tt>" position to "<tt>to's</tt>"
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
        final char[] hexChars = new char[(to - from) * 2];
        for (int i = from; i < to; i++) {
            int v = bytes[i] & 0xFF;
            int idx = (i - from) * 2;
            hexChars[idx] = HEX_ARRAY[v >>> 4];
            hexChars[idx + 1] = HEX_ARRAY[v & 0x0F];
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
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            int idx = i * 3;
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
        int v = b & 0xFF;
        return new String(new char[] { HEX_ARRAY[v >>> 4], HEX_ARRAY[v & 0x0F] });
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
        byte[] res = new byte[bytes.length];
        for (int i = 0, j = bytes.length - 1; j >= 0; i++, j--) {
            res[i] = bytes[j];
        }
        return res;
    }
}

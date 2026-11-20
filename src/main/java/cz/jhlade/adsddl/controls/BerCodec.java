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
package cz.jhlade.adsddl.controls;

import java.util.Arrays;

/**
 * Zero-allocation ASN.1 BER (Basic Encoding Rules) reader and writer for Active Directory LDAP controls.
 */
public final class BerCodec {

    public static final byte TAG_BOOLEAN = 0x01;

    public static final byte TAG_INTEGER = 0x02;

    public static final byte TAG_OCTET_STRING = 0x04;

    public static final byte TAG_ENUMERATED = 0x0A;

    public static final byte TAG_SEQUENCE = 0x30;

    private static final byte[] EMPTY_BYTES = new byte[0];

    private BerCodec() {
    }

    /**
     * Returns the number of bytes required to encode a BER length field for a payload of {@code length} bytes.
     *
     * @param length payload length in bytes.
     * @return number of bytes for the BER length field (1..5).
     */
    public static int lengthFieldSize(final int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Negative BER length: " + length);
        }
        if (length < 0x80) {
            return 1;
        }
        if (length <= 0xFF) {
            return 2;
        }
        if (length <= 0xFFFF) {
            return 3;
        }
        if (length <= 0xFFFFFF) {
            return 4;
        }
        return 5;
    }

    /**
     * Returns the number of value bytes needed for a signed 32-bit BER INTEGER (minimal two's complement encoding).
     *
     * @param value integer value.
     * @return number of value bytes (1..4).
     */
    public static int integerValueSize(final int value) {
        if (value >= -128 && value <= 127) {
            return 1;
        }
        if (value >= -32768 && value <= 32767) {
            return 2;
        }
        if (value >= -8388608 && value <= 8388607) {
            return 3;
        }
        return 4;
    }

    /**
     * Writes a BER length field into {@code dst} at {@code offset} and returns the new offset.
     *
     * @param dst target array.
     * @param offset write offset.
     * @param length payload length.
     * @return new offset after writing the length field.
     */
    public static int writeLength(final byte[] dst, final int offset, final int length) {
        int pos = offset;
        if (length < 0x80) {
            dst[pos++] = (byte) length;
        } else if (length <= 0xFF) {
            dst[pos++] = (byte) 0x81;
            dst[pos++] = (byte) length;
        } else if (length <= 0xFFFF) {
            dst[pos++] = (byte) 0x82;
            dst[pos++] = (byte) (length >>> 8);
            dst[pos++] = (byte) length;
        } else if (length <= 0xFFFFFF) {
            dst[pos++] = (byte) 0x83;
            dst[pos++] = (byte) (length >>> 16);
            dst[pos++] = (byte) (length >>> 8);
            dst[pos++] = (byte) length;
        } else {
            dst[pos++] = (byte) 0x84;
            dst[pos++] = (byte) (length >>> 24);
            dst[pos++] = (byte) (length >>> 16);
            dst[pos++] = (byte) (length >>> 8);
            dst[pos++] = (byte) length;
        }
        return pos;
    }

    /**
     * Writes a minimal signed BER INTEGER element (tag + length + value) into {@code dst} at {@code offset}.
     *
     * @param dst target array.
     * @param offset write offset.
     * @param value integer value.
     * @return new offset after writing the INTEGER element.
     */
    public static int writeInteger(final byte[] dst, final int offset, final int value) {
        final int valSize = integerValueSize(value);
        int pos = offset;
        dst[pos++] = TAG_INTEGER;
        dst[pos++] = (byte) valSize;
        for (int i = valSize - 1; i >= 0; i--) {
            dst[pos++] = (byte) (value >>> (i << 3));
        }
        return pos;
    }

    /**
     * Writes a fixed 4-byte BER INTEGER element (as expected by AD DirSync request control) into {@code dst}.
     *
     * @param dst target array.
     * @param offset write offset.
     * @param value integer value.
     * @return new offset after writing the 6-byte element.
     */
    public static int writeFixedInt32(final byte[] dst, final int offset, final int value) {
        int pos = offset;
        dst[pos++] = TAG_INTEGER;
        dst[pos++] = 0x04;
        dst[pos++] = (byte) (value >>> 24);
        dst[pos++] = (byte) (value >>> 16);
        dst[pos++] = (byte) (value >>> 8);
        dst[pos++] = (byte) value;
        return pos;
    }

    /**
     * Writes a BER OCTET STRING element (tag + length + bytes) into {@code dst} at {@code offset}.
     *
     * @param dst target array.
     * @param offset write offset.
     * @param bytes payload bytes (may be null or empty).
     * @return new offset after writing the OCTET STRING element.
     */
    public static int writeOctetString(final byte[] dst, final int offset, final byte[] bytes) {
        final int len = bytes == null ? 0 : bytes.length;
        int pos = offset;
        dst[pos++] = TAG_OCTET_STRING;
        pos = writeLength(dst, pos, len);
        if (len > 0) {
            System.arraycopy(bytes, 0, dst, pos, len);
            pos += len;
        }
        return pos;
    }

    /**
     * Encodes a BER SEQUENCE containing a single minimal INTEGER: {@code SEQUENCE { INTEGER value }}.
     * Used by {@code SDFlagsControl} and {@code SearchOptionsControl}.
     *
     * @param value integer flag value.
     * @return BER-encoded sequence.
     */
    public static byte[] encodeSingleIntegerSequence(final int value) {
        final int intValSize = integerValueSize(value);
        final int seqPayloadSize = 2 + intValSize;
        final byte[] out = new byte[2 + seqPayloadSize];
        out[0] = TAG_SEQUENCE;
        out[1] = (byte) seqPayloadSize;
        writeInteger(out, 2, value);
        return out;
    }

    /**
     * Encodes a BER SEQUENCE containing two integers and an octet string:
     * {@code SEQUENCE { INTEGER v1, INTEGER v2, OCTET STRING cookie }}.
     *
     * @param v1 first integer.
     * @param v2 second integer.
     * @param cookie octet string payload.
     * @param fixedInt32 true to encode integers as fixed 4-byte values (DirSync), false for minimal BER integers.
     * @return BER-encoded sequence.
     */
    public static byte[] encodeIntIntOctetStringSequence(
            final int v1,
            final int v2,
            final byte[] cookie,
            final boolean fixedInt32) {
        final byte[] safeCookie = cookie == null ? EMPTY_BYTES : cookie;
        final int int1Size = fixedInt32 ? 6 : (2 + integerValueSize(v1));
        final int int2Size = fixedInt32 ? 6 : (2 + integerValueSize(v2));
        final int cookieSize = 1 + lengthFieldSize(safeCookie.length) + safeCookie.length;
        final int seqPayloadSize = int1Size + int2Size + cookieSize;

        final byte[] out = new byte[1 + lengthFieldSize(seqPayloadSize) + seqPayloadSize];
        int pos = 0;
        out[pos++] = TAG_SEQUENCE;
        pos = writeLength(out, pos, seqPayloadSize);
        if (fixedInt32) {
            pos = writeFixedInt32(out, pos, v1);
            pos = writeFixedInt32(out, pos, v2);
        } else {
            pos = writeInteger(out, pos, v1);
            pos = writeInteger(out, pos, v2);
        }
        writeOctetString(out, pos, safeCookie);
        return out;
    }

    /**
     * Stateful cursor for zero-allocation sequential reading of BER elements from a byte array.
     */
    public static final class BerReader {

        private final byte[] buf;

        private final int limit;

        private int pos;

        public BerReader(final byte[] buf) {
            this(buf, 0, buf == null ? 0 : buf.length);
        }

        public BerReader(final byte[] buf, final int offset, final int length) {
            this.buf = buf == null ? EMPTY_BYTES : buf;
            this.pos = Math.max(0, offset);
            this.limit = Math.min(this.buf.length, this.pos + Math.max(0, length));
        }

        public boolean hasRemaining() {
            return pos < limit;
        }

        public int position() {
            return pos;
        }

        public int peekTag() {
            return pos < limit ? (buf[pos] & 0xFF) : -1;
        }

        /**
         * Reads the next tag and verifies it matches {@code expectedTag}, returning the element's payload length.
         * Advances the cursor to the start of the element's payload.
         *
         * @param expectedTag expected ASN.1 tag byte.
         * @return payload length in bytes.
         */
        public int readTagAndLength(final byte expectedTag) {
            if (pos >= limit) {
                throw new IllegalArgumentException("Unexpected end of BER stream at position " + pos);
            }
            final byte tag = buf[pos++];
            if (tag != expectedTag) {
                throw new IllegalArgumentException(
                        "Expected BER tag 0x" + Integer.toHexString(expectedTag & 0xFF)
                        + " but found 0x" + Integer.toHexString(tag & 0xFF) + " at position " + (pos - 1));
            }
            return readLength();
        }

        /**
         * Reads a BER length field at the current position and advances the cursor past it.
         *
         * @return decoded length.
         */
        public int readLength() {
            if (pos >= limit) {
                throw new IllegalArgumentException("Unexpected end of BER length at position " + pos);
            }
            final int b = buf[pos++] & 0xFF;
            if ((b & 0x80) == 0) {
                return b;
            }
            final int count = b & 0x7F;
            if (count == 0 || count > 4 || pos + count > limit) {
                throw new IllegalArgumentException("Invalid BER length octets count: " + count);
            }
            int len = 0;
            for (int i = 0; i < count; i++) {
                len = (len << 8) | (buf[pos++] & 0xFF);
            }
            if (len < 0) {
                throw new IllegalArgumentException("BER length overflow: " + len);
            }
            return len;
        }

        /**
         * Reads a BER INTEGER or ENUMERATED element as a 32-bit signed int.
         *
         * @return decoded integer value.
         */
        public int readInt() {
            if (pos >= limit) {
                throw new IllegalArgumentException("Unexpected end of BER stream reading INTEGER");
            }
            final byte tag = buf[pos++];
            if (tag != TAG_INTEGER && tag != TAG_ENUMERATED) {
                throw new IllegalArgumentException("Expected BER INTEGER/ENUMERATED tag, got 0x"
                        + Integer.toHexString(tag & 0xFF));
            }
            final int len = readLength();
            if (len == 0) {
                return 0;
            }
            if (pos + len > limit) {
                throw new IllegalArgumentException("BER INTEGER exceeds buffer limit");
            }
            // Sign-extend first byte
            int val = buf[pos++];
            for (int i = 1; i < len; i++) {
                val = (val << 8) | (buf[pos++] & 0xFF);
            }
            return val;
        }

        /**
         * Reads a BER OCTET STRING element into a new byte array.
         *
         * @return octet string payload.
         */
        public byte[] readOctetString() {
            final int len = readTagAndLength(TAG_OCTET_STRING);
            if (len == 0) {
                return EMPTY_BYTES;
            }
            if (pos + len > limit) {
                throw new IllegalArgumentException("BER OCTET STRING exceeds buffer limit");
            }
            final byte[] res = Arrays.copyOfRange(buf, pos, pos + len);
            pos += len;
            return res;
        }

        /**
         * Skips the next BER TLV element regardless of its tag.
         */
        public void skipElement() {
            if (pos >= limit) {
                return;
            }
            pos++; // tag
            final int len = readLength();
            pos = Math.min(limit, pos + len);
        }
    }
}

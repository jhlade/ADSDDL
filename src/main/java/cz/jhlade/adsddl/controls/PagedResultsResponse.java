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
import javax.naming.ldap.Control;

/**
 * Decoded Simple Paged Results response control ({@code 1.2.840.113556.1.4.319}, RFC 2696):
 * {@code realSearchControlValue ::= SEQUENCE { size INTEGER, cookie OCTET STRING }}.
 */
public final class PagedResultsResponse {

    /**
     * LDAP_PAGED_RESULT_OID_STRING (RFC 2696).
     */
    public static final String OID = "1.2.840.113556.1.4.319";

    private static final byte[] EMPTY_COOKIE = new byte[0];

    private final int estimatedTotalSize;

    private final byte[] cookie;

    public PagedResultsResponse(final int estimatedTotalSize, final byte[] cookie) {
        this.estimatedTotalSize = estimatedTotalSize;
        this.cookie = cookie == null || cookie.length == 0
                ? EMPTY_COOKIE
                : Arrays.copyOf(cookie, cookie.length);
    }

    /**
     * Encodes a PagedResults request control value: {@code SEQUENCE { INTEGER pageSize, OCTET STRING cookie }}.
     *
     * @param pageSize requested page size.
     * @param cookie continuation cookie (may be null or empty for first page).
     * @return BER-encoded control value.
     */
    public static byte[] encodeRequestValue(final int pageSize, final byte[] cookie) {
        final byte[] safeCookie = cookie == null ? EMPTY_COOKIE : cookie;
        final int intSize = 2 + BerCodec.integerValueSize(pageSize);
        final int cookieSize = 1 + BerCodec.lengthFieldSize(safeCookie.length) + safeCookie.length;
        final int seqPayloadSize = intSize + cookieSize;

        final byte[] out = new byte[1 + BerCodec.lengthFieldSize(seqPayloadSize) + seqPayloadSize];
        int pos = 0;
        out[pos++] = BerCodec.TAG_SEQUENCE;
        pos = BerCodec.writeLength(out, pos, seqPayloadSize);
        pos = BerCodec.writeInteger(out, pos, pageSize);
        BerCodec.writeOctetString(out, pos, safeCookie);
        return out;
    }

    /**
     * Decodes a {@link PagedResultsResponse} from its BER-encoded control value.
     *
     * @param ber BER-encoded control value.
     * @return decoded PagedResultsResponse.
     */
    public static PagedResultsResponse decode(final byte[] ber) {
        if (ber == null || ber.length < 2) {
            return new PagedResultsResponse(0, EMPTY_COOKIE);
        }
        final BerCodec.BerReader reader = new BerCodec.BerReader(ber);
        reader.readTagAndLength(BerCodec.TAG_SEQUENCE);
        final int size = reader.hasRemaining() ? reader.readInt() : 0;
        final byte[] cookie = reader.hasRemaining() ? reader.readOctetString() : EMPTY_COOKIE;
        return new PagedResultsResponse(size, cookie);
    }

    /**
     * Finds and decodes the PagedResults response control from an array of LDAP response controls.
     *
     * @param controls LDAP response controls from {@code LdapContext.getResponseControls()}.
     * @return decoded {@link PagedResultsResponse}, or {@code null} if not present.
     */
    public static PagedResultsResponse fromResponseControls(final Control[] controls) {
        if (controls == null) {
            return null;
        }
        for (Control control : controls) {
            if (control != null && OID.equals(control.getID())) {
                return decode(control.getEncodedValue());
            }
        }
        return null;
    }

    /**
     * Estimated total result set size returned by the server (0 if unknown).
     *
     * @return estimated total size.
     */
    public int getEstimatedTotalSize() {
        return estimatedTotalSize;
    }

    /**
     * Indicates whether another page of results is available ({@code cookie.length > 0}).
     *
     * @return true if more pages exist.
     */
    public boolean hasMorePages() {
        return cookie.length > 0;
    }

    /**
     * Gets a defensive copy of the pagination cookie, or an empty array if at the end of results.
     *
     * @return cookie byte array (never null).
     */
    public byte[] getCookie() {
        return cookie.length == 0 ? EMPTY_COOKIE : Arrays.copyOf(cookie, cookie.length);
    }
}

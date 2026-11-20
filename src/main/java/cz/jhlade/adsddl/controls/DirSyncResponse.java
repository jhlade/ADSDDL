package cz.jhlade.adsddl.controls;

import java.util.Arrays;
import javax.naming.ldap.Control;

/**
 * Decoded Active Directory DirSync response control ({@code 1.2.840.113556.1.4.841})
 * as specified in [MS-ADTS] section 3.1.1.3.4.1.3.
 * <p>
 * Wire format:
 * {@code RealReplControlValue ::= SEQUENCE { flag INTEGER, maxReturnLength INTEGER, cookie OCTET STRING }}
 * </p>
 */
public final class DirSyncResponse {

    /**
     * LDAP_SERVER_DIRSYNC_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.841";

    private static final byte[] EMPTY_COOKIE = new byte[0];

    private final int flag;

    private final int maxReturnLength;

    private final byte[] cookie;

    public DirSyncResponse(final int flag, final int maxReturnLength, final byte[] cookie) {
        this.flag = flag;
        this.maxReturnLength = maxReturnLength;
        this.cookie = cookie == null || cookie.length == 0
                ? EMPTY_COOKIE
                : Arrays.copyOf(cookie, cookie.length);
    }

    /**
     * Decodes a {@link DirSyncResponse} from its BER-encoded control value.
     *
     * @param ber BER-encoded control value.
     * @return decoded DirSyncResponse.
     */
    public static DirSyncResponse decode(final byte[] ber) {
        if (ber == null || ber.length < 2) {
            return new DirSyncResponse(0, 0, EMPTY_COOKIE);
        }
        final BerCodec.BerReader reader = new BerCodec.BerReader(ber);
        reader.readTagAndLength(BerCodec.TAG_SEQUENCE);
        final int flag = reader.hasRemaining() ? reader.readInt() : 0;
        final int maxLen = reader.hasRemaining() ? reader.readInt() : 0;
        final byte[] cookie = reader.hasRemaining() ? reader.readOctetString() : EMPTY_COOKIE;
        return new DirSyncResponse(flag, maxLen, cookie);
    }

    /**
     * Finds and decodes the DirSync response control from an array of LDAP response controls.
     *
     * @param controls LDAP response controls from {@code LdapContext.getResponseControls()}.
     * @return decoded {@link DirSyncResponse}, or {@code null} if not present.
     */
    public static DirSyncResponse fromResponseControls(final Control[] controls) {
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
     * Non-zero flag value indicates that more changes remain to be retrieved on the server.
     *
     * @return raw flag value.
     */
    public int getFlag() {
        return flag;
    }

    /**
     * Indicates whether more results are available on the server ({@code flag != 0}).
     *
     * @return true if another DirSync page should be requested with {@link #getCookie()}.
     */
    public boolean hasMoreResults() {
        return flag != 0;
    }

    /**
     * Gets the server's maxReturnLength / unused attribute count field.
     *
     * @return maxReturnLength value.
     */
    public int getMaxReturnLength() {
        return maxReturnLength;
    }

    /**
     * Gets a defensive copy of the DirSync continuation cookie.
     *
     * @return DirSync cookie (never null).
     */
    public byte[] getCookie() {
        return cookie.length == 0 ? EMPTY_COOKIE : Arrays.copyOf(cookie, cookie.length);
    }
}

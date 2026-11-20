package cz.jhlade.adsddl.controls;

import java.nio.charset.StandardCharsets;
import javax.naming.ldap.BasicControl;

/**
 * Active Directory Extended DN control ({@code LDAP_SERVER_EXTENDED_DN_OID}, {@code 1.2.840.113556.1.4.529})
 * as specified in [MS-ADTS] section 3.1.1.3.4.1.5.
 * <p>
 * Requests that the server return object DNs prefixed with {@code <GUID=...>;<SID=...>;distinguishedName}.
 * Format flag {@code 0} returns hex-string GUID/SID; format flag {@code 1} returns standard string GUID
 * and S-1-... SID format.
 * </p>
 */
public class ExtendedDNControl extends BasicControl {

    private static final long serialVersionUID = 1L;

    /**
     * LDAP_SERVER_EXTENDED_DN_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.529";

    /**
     * Format 0: Hexadecimal string representation of GUID and SID.
     */
    public static final int FORMAT_HEX = 0;

    /**
     * Format 1: Standard dashed GUID string and S-1-... SID string representation.
     */
    public static final int FORMAT_STANDARD_STRING = 1;

    private final int formatFlag;

    /**
     * Creates a critical ExtendedDNControl using {@link #FORMAT_STANDARD_STRING} (1).
     */
    public ExtendedDNControl() {
        this(true, FORMAT_STANDARD_STRING);
    }

    /**
     * Creates a critical ExtendedDNControl with the specified format flag (0 or 1).
     *
     * @param formatFlag {@link #FORMAT_HEX} (0) or {@link #FORMAT_STANDARD_STRING} (1).
     */
    public ExtendedDNControl(final int formatFlag) {
        this(true, formatFlag);
    }

    /**
     * Creates an ExtendedDNControl with the specified criticality and format flag.
     *
     * @param criticality control criticality.
     * @param formatFlag {@link #FORMAT_HEX} (0) or {@link #FORMAT_STANDARD_STRING} (1).
     */
    public ExtendedDNControl(final boolean criticality, final int formatFlag) {
        super(OID, criticality, BerCodec.encodeSingleIntegerSequence(formatFlag));
        this.formatFlag = formatFlag;
    }

    public int getFormatFlag() {
        return formatFlag;
    }

    /**
     * Parsed components of an Active Directory Extended DN string:
     * {@code <GUID=...>;<SID=...>;CN=...,DC=...}.
     */
    public static final class ParsedExtendedDN {

        private final String guid;

        private final String sid;

        private final String distinguishedName;

        public ParsedExtendedDN(final String guid, final String sid, final String distinguishedName) {
            this.guid = guid;
            this.sid = sid;
            this.distinguishedName = distinguishedName;
        }

        /**
         * Parses an Extended DN string returned by Active Directory or Samba 4.
         *
         * @param extendedDn extended DN string (e.g. {@code <GUID=...>;<SID=S-1-5-...>;CN=User,DC=example,DC=com}).
         * @return parsed components.
         */
        public static ParsedExtendedDN parse(final String extendedDn) {
            if (extendedDn == null) {
                return new ParsedExtendedDN(null, null, null);
            }
            String guid = null;
            String sid = null;
            int cursor = 0;
            final int len = extendedDn.length();

            while (cursor < len && extendedDn.charAt(cursor) == '<') {
                final int closeBracket = extendedDn.indexOf('>', cursor + 1);
                if (closeBracket < 0) {
                    break;
                }
                final int eq = extendedDn.indexOf('=', cursor + 1);
                if (eq > cursor && eq < closeBracket) {
                    final String key = extendedDn.substring(cursor + 1, eq);
                    final String val = extendedDn.substring(eq + 1, closeBracket);
                    if ("GUID".equalsIgnoreCase(key)) {
                        guid = val;
                    } else if ("SID".equalsIgnoreCase(key)) {
                        sid = val;
                    }
                }
                cursor = closeBracket + 1;
                if (cursor < len && extendedDn.charAt(cursor) == ';') {
                    cursor++;
                }
            }

            final String dn = cursor == 0 ? extendedDn : extendedDn.substring(cursor);
            return new ParsedExtendedDN(guid, sid, dn);
        }

        public String getGuid() {
            return guid;
        }

        public String getSid() {
            return sid;
        }

        public String getDistinguishedName() {
            return distinguishedName;
        }
    }

    /**
     * Encodes an Extended DN response value for testing or mock LDAP servers.
     *
     * @param value string value.
     * @return UTF-8 bytes.
     */
    public static byte[] toBytes(final String value) {
        return value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
    }
}

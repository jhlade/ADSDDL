package cz.jhlade.adsddl.data;

import java.util.Arrays;
import net.tirasa.adsddl.ntsd.utils.GUID;

/**
 * Well-known Active Directory Schema Class, Attribute, and Property Set GUIDs
 * ({@code schemaIDGUID} / {@code rightsGuid}) used in {@code ObjectType} and {@code InheritedObjectType}
 * fields of Object ACEs ([MS-ADTS] section 5.1.3.2).
 */
public enum AdSchemaGuid {

    // --- Directory Object Classes (used in ObjectType for CC/DC or InheritedObjectType for inheritance) ---

    /**
     * User class ({@code bf967aba-0de6-11d0-a285-00aa003049e2}, {@code CN=User,CN=Schema,...}).
     */
    CLASS_USER("bf967aba-0de6-11d0-a285-00aa003049e2"),

    /**
     * Group class ({@code bf967a9c-0de6-11d0-a285-00aa003049e2}, {@code CN=Group,CN=Schema,...}).
     */
    CLASS_GROUP("bf967a9c-0de6-11d0-a285-00aa003049e2"),

    /**
     * Computer class ({@code bf967a86-0de6-11d0-a285-00aa003049e2}, {@code CN=Computer,CN=Schema,...}).
     */
    CLASS_COMPUTER("bf967a86-0de6-11d0-a285-00aa003049e2"),

    /**
     * Contact class ({@code 5cb41ed0-0e4c-11d0-a286-00aa003049e2}, {@code CN=Contact,CN=Schema,...}).
     */
    CLASS_CONTACT("5cb41ed0-0e4c-11d0-a286-00aa003049e2"),

    /**
     * Organizational-Unit class ({@code bf967aa5-0de6-11d0-a285-00aa003049e2},
     * {@code CN=Organizational-Unit,CN=Schema,...}).
     */
    CLASS_ORGANIZATIONAL_UNIT("bf967aa5-0de6-11d0-a285-00aa003049e2"),

    /**
     * Container class ({@code bf967a8b-0de6-11d0-a285-00aa003049e2}, {@code CN=Container,CN=Schema,...}).
     */
    CLASS_CONTAINER("bf967a8b-0de6-11d0-a285-00aa003049e2"),

    /**
     * Print-Queue class ({@code bf967aa8-0de6-11d0-a285-00aa003049e2}, {@code CN=Print-Queue,CN=Schema,...}).
     */
    CLASS_PRINT_QUEUE("bf967aa8-0de6-11d0-a285-00aa003049e2"),

    /**
     * msDS-GroupManagedServiceAccount class ({@code 7b8b558a-93a5-4af7-adca-c017e67f1057}).
     */
    CLASS_GMSA("7b8b558a-93a5-4af7-adca-c017e67f1057"),

    // --- Directory Attributes (used in ObjectType with RP / WP) ---

    /**
     * Attribute {@code member} ({@code bf9679c0-0de6-11d0-a285-00aa003049e2}).
     * Used with {@code WP} to grant a group manager ("Manager can update membership list") the right to edit members.
     */
    ATTR_MEMBER("bf9679c0-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code pwdLastSet} ({@code bf967a0a-0de6-11d0-a285-00aa003049e2}).
     * Used with {@code RP}/{@code WP} to allow forcing "User must change password at next logon" ({@code pwdLastSet=0}).
     */
    ATTR_PWD_LAST_SET("bf967a0a-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code userAccountControl} ({@code bf967a68-0de6-11d0-a285-00aa003049e2}).
     * Used with {@code RP}/{@code WP} to enable/disable user accounts.
     */
    ATTR_USER_ACCOUNT_CONTROL("bf967a68-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code lockoutTime} ({@code 28630ebf-41d5-11d1-a9c1-0000f80367c1}).
     * Used with {@code RP}/{@code WP} to unlock locked-out user accounts.
     */
    ATTR_LOCKOUT_TIME("28630ebf-41d5-11d1-a9c1-0000f80367c1"),

    /**
     * Attribute {@code accountExpires} ({@code bf967915-0de6-11d0-a285-00aa003049e2}).
     */
    ATTR_ACCOUNT_EXPIRES("bf967915-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code sAMAccountName} ({@code 3e0abfd0-126a-11d0-a060-00aa006c33ed}).
     */
    ATTR_SAM_ACCOUNT_NAME("3e0abfd0-126a-11d0-a060-00aa006c33ed"),

    /**
     * Attribute {@code userPrincipalName} ({@code 28630ebb-41d5-11d1-a9c1-0000f80367c1}).
     */
    ATTR_USER_PRINCIPAL_NAME("28630ebb-41d5-11d1-a9c1-0000f80367c1"),

    /**
     * Attribute {@code displayName} ({@code bf967953-0de6-11d0-a285-00aa003049e2}).
     */
    ATTR_DISPLAY_NAME("bf967953-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code mail} ({@code bf967961-0de6-11d0-a285-00aa003049e2}).
     */
    ATTR_MAIL("bf967961-0de6-11d0-a285-00aa003049e2"),

    /**
     * Attribute {@code managedBy} ({@code 0296c120-40da-11d1-a9c0-0000f80367c1}).
     */
    ATTR_MANAGED_BY("0296c120-40da-11d1-a9c0-0000f80367c1"),

    /**
     * Attribute {@code servicePrincipalName} ({@code f3a64788-5306-11d1-a9c5-0000f80367c1}).
     */
    ATTR_SERVICE_PRINCIPAL_NAME("f3a64788-5306-11d1-a9c5-0000f80367c1"),

    /**
     * Attribute {@code msDS-KeyCredentialLink} ({@code 5b47d60f-6090-40b2-9f37-2a4de88f3063}).
     */
    ATTR_KEY_CREDENTIAL_LINK("5b47d60f-6090-40b2-9f37-2a4de88f3063"),

    // --- Property Sets (used in ObjectType with RP / WP) ---

    /**
     * Property Set: User-Account-Restrictions ({@code 4c164200-20c0-11d0-a768-00aa006e0529}).
     * Covers {@code userAccountControl}, {@code accountExpires}, {@code userParameters}, {@code logonHours}.
     */
    PROPSET_USER_ACCOUNT_RESTRICTIONS("4c164200-20c0-11d0-a768-00aa006e0529"),

    /**
     * Property Set:User-Logon ({@code 5f202010-79a5-11d0-9020-00c04fc2d4cf}).
     */
    PROPSET_USER_LOGON("5f202010-79a5-11d0-9020-00c04fc2d4cf"),

    /**
     * Property Set: Public-Information ({@code e48d0154-bcf8-11d1-8702-00c04fb96050}).
     */
    PROPSET_PUBLIC_INFORMATION("e48d0154-bcf8-11d1-8702-00c04fb96050"),

    /**
     * Property Set: Personal-Information ({@code 77b5b886-944a-11d1-aebd-0000f80367c1}).
     */
    PROPSET_PERSONAL_INFORMATION("77b5b886-944a-11d1-aebd-0000f80367c1"),

    /**
     * Property Set: General-Information ({@code 59ba2f42-79a2-11d0-9020-00c04fc2d3cf}).
     */
    PROPSET_GENERAL_INFORMATION("59ba2f42-79a2-11d0-9020-00c04fc2d3cf"),

    /**
     * Property Set: Group-Membership ({@code bc0ac240-79a9-11d0-9020-00c04fc2d4cf}).
     */
    PROPSET_GROUP_MEMBERSHIP("bc0ac240-79a9-11d0-9020-00c04fc2d4cf");

    private final String guidString;

    private final byte[] guidBytes;

    AdSchemaGuid(final String guidString) {
        this.guidString = guidString;
        this.guidBytes = GUID.getGuidAsByteArray(guidString);
    }

    /**
     * Gets the canonical lowercase GUID string.
     *
     * @return GUID string.
     */
    public String getGuidString() {
        return guidString;
    }

    /**
     * Gets a defensive copy of the 16-byte mixed-endian AD binary GUID.
     *
     * @return 16-byte binary GUID.
     */
    public byte[] getGuidBytes() {
        return Arrays.copyOf(guidBytes, 16);
    }

    /**
     * Checks whether the given 16-byte binary GUID matches this schema GUID without allocating.
     *
     * @param candidate 16-byte binary GUID.
     * @return true if equal.
     */
    public boolean matches(final byte[] candidate) {
        return Arrays.equals(guidBytes, candidate);
    }

    /**
     * Checks whether the given string GUID matches this schema GUID without allocating.
     *
     * @param candidate string GUID.
     * @return true if equal.
     */
    public boolean matches(final String candidate) {
        return GUID.equals(guidBytes, candidate);
    }

    /**
     * Looks up an {@link AdSchemaGuid} by its 16-byte binary GUID.
     *
     * @param guidBytes 16-byte binary GUID.
     * @return matching {@link AdSchemaGuid}, or {@code null} if unknown.
     */
    public static AdSchemaGuid fromGuidBytes(final byte[] guidBytes) {
        if (guidBytes == null || guidBytes.length != 16) {
            return null;
        }
        for (AdSchemaGuid item : values()) {
            if (Arrays.equals(item.guidBytes, guidBytes)) {
                return item;
            }
        }
        return null;
    }

    /**
     * Looks up an {@link AdSchemaGuid} by its string GUID.
     *
     * @param guidString string GUID.
     * @return matching {@link AdSchemaGuid}, or {@code null} if unknown.
     */
    public static AdSchemaGuid fromGuidString(final String guidString) {
        if (guidString == null || guidString.length() != 36) {
            return null;
        }
        for (AdSchemaGuid item : values()) {
            if (GUID.equals(item.guidBytes, guidString)) {
                return item;
            }
        }
        return null;
    }
}

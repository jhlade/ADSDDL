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
package cz.jhlade.adsddl.data;

import java.util.Arrays;
import net.tirasa.adsddl.ntsd.utils.GUID;

/**
 * Well-known Active Directory Extended Rights (ControlAccessRight) GUIDs from
 * {@code CN=Extended-Rights,CN=Configuration,DC=...} ([MS-ADTS] section 5.1.3.2.1).
 * Used in Object ACEs with right {@code ADS_RIGHT_DS_CONTROL_ACCESS (CR, 0x00000100)}
 * or {@code ADS_RIGHT_DS_SELF (SW, 0x00000008)}.
 */
public enum AdExtendedRight {

    /**
     * User-Change-Password ({@code ab721a53-1e2f-11d0-9819-00aa0040529b}).
     * Grants or denies the right to change a user's own password.
     */
    USER_CHANGE_PASSWORD("ab721a53-1e2f-11d0-9819-00aa0040529b"),

    /**
     * User-Force-Change-Password ({@code 00299570-246d-11d0-a768-00aa006e0529}).
     * Grants the right to reset a user's or computer's password without knowing the current password.
     */
    USER_FORCE_CHANGE_PASSWORD("00299570-246d-11d0-a768-00aa006e0529"),

    /**
     * Send-As ({@code ab721a54-1e2f-11d0-9819-00aa0040529b}).
     * Grants the right to send mail as the target user, contact, or distribution group (Exchange / Office 365).
     */
    SEND_AS("ab721a54-1e2f-11d0-9819-00aa0040529b"),

    /**
     * Receive-As ({@code ab721a56-1e2f-11d0-9819-00aa0040529b}).
     * Grants the right to open a mailbox as the target user.
     */
    RECEIVE_AS("ab721a56-1e2f-11d0-9819-00aa0040529b"),

    /**
     * Self-Membership ({@code bf9679c0-0de6-11d0-a285-00aa003049e2}).
     * Validated write (SW) or property write (WP) on the {@code member} attribute of a group.
     */
    SELF_MEMBERSHIP("bf9679c0-0de6-11d0-a285-00aa003049e2"),

    /**
     * Validated-DNS-Host-Name ({@code 72e39547-7b18-11d1-adef-00c04fd8d5cd}).
     * Validated write (SW) to the {@code dNSHostName} attribute on computer objects.
     */
    VALIDATED_DNS_HOST_NAME("72e39547-7b18-11d1-adef-00c04fd8d5cd"),

    /**
     * Validated-SPN ({@code f3a64788-5306-11d1-a9c5-0000f80367c1}).
     * Validated write (SW) to the {@code servicePrincipalName} attribute.
     */
    VALIDATED_SPN("f3a64788-5306-11d1-a9c5-0000f80367c1"),

    /**
     * DS-Replication-Get-Changes ({@code 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}).
     * Required on the domain naming context for DirSync / replication queries.
     */
    DS_REPLICATION_GET_CHANGES("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),

    /**
     * DS-Replication-Get-Changes-All ({@code 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}).
     * Grants the right to replicate all changes including secrets.
     */
    DS_REPLICATION_GET_CHANGES_ALL("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),

    /**
     * DS-Replication-Get-Changes-In-Filtered-Set ({@code 89e95b76-444d-4c62-991a-0facbeda640c}).
     * Grants the right to replicate filtered attribute sets (RODC).
     */
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET("89e95b76-444d-4c62-991a-0facbeda640c"),

    /**
     * Reanimate-Tombstones ({@code 45ec5156-db7e-47bb-b53f-dbeb2d03c40f}).
     * Grants the right to restore deleted Active Directory objects.
     */
    REANIMATE_TOMBSTONES("45ec5156-db7e-47bb-b53f-dbeb2d03c40f"),

    /**
     * Unexpire-Password ({@code ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501}).
     * Grants the right to restore an expired password.
     */
    UNEXPIRE_PASSWORD("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"),

    /**
     * Generate-RSoP-Planning ({@code b7b1b3de-ab09-4242-9e30-9980e5d322f7}).
     */
    GENERATE_RSOP_PLANNING("b7b1b3de-ab09-4242-9e30-9980e5d322f7"),

    /**
     * Generate-RSoP-Logging ({@code b7b1b3dd-ab09-4242-9e30-9980e5d322f7}).
     */
    GENERATE_RSOP_LOGGING("b7b1b3dd-ab09-4242-9e30-9980e5d322f7");

    private final String guidString;

    private final byte[] guidBytes;

    AdExtendedRight(final String guidString) {
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
     * Checks whether the given 16-byte binary GUID matches this extended right without allocating.
     *
     * @param candidate 16-byte binary GUID.
     * @return true if equal.
     */
    public boolean matches(final byte[] candidate) {
        return Arrays.equals(guidBytes, candidate);
    }

    /**
     * Checks whether the given string GUID matches this extended right without allocating.
     *
     * @param candidate string GUID.
     * @return true if equal.
     */
    public boolean matches(final String candidate) {
        return GUID.equals(guidBytes, candidate);
    }

    /**
     * Looks up an {@link AdExtendedRight} by its 16-byte binary GUID.
     *
     * @param guidBytes 16-byte binary GUID.
     * @return matching {@link AdExtendedRight}, or {@code null} if unknown.
     */
    public static AdExtendedRight fromGuidBytes(final byte[] guidBytes) {
        if (guidBytes == null || guidBytes.length != 16) {
            return null;
        }
        for (AdExtendedRight right : values()) {
            if (Arrays.equals(right.guidBytes, guidBytes)) {
                return right;
            }
        }
        return null;
    }

    /**
     * Looks up an {@link AdExtendedRight} by its string GUID.
     *
     * @param guidString string GUID.
     * @return matching {@link AdExtendedRight}, or {@code null} if unknown.
     */
    public static AdExtendedRight fromGuidString(final String guidString) {
        if (guidString == null || guidString.length() != 36) {
            return null;
        }
        for (AdExtendedRight right : values()) {
            if (GUID.equals(right.guidBytes, guidString)) {
                return right;
            }
        }
        return null;
    }
}

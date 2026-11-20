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

import javax.naming.ldap.BasicControl;

/**
 * Active Directory Permissive Modify control ({@code LDAP_SERVER_PERMISSIVE_MODIFY_OID},
 * {@code 1.2.840.113556.1.4.1413}) as specified in [MS-ADTS] section 3.1.1.3.4.1.16.
 * <p>
 * Causes an LDAP Modify request to succeed without returning {@code AttributeInUseException} (error 20)
 * or {@code NoSuchAttributeException} (error 16) when adding an attribute value that already exists
 * (e.g. adding a {@code member} to a group) or removing a value that is already absent.
 * Supported by both Microsoft Active Directory and Samba 4.
 * </p>
 */
public class PermissiveModifyControl extends BasicControl {

    private static final long serialVersionUID = 1L;

    /**
     * LDAP_SERVER_PERMISSIVE_MODIFY_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.1413";

    /**
     * Creates a critical PermissiveModifyControl.
     */
    public PermissiveModifyControl() {
        super(OID, true, null);
    }

    /**
     * Creates a PermissiveModifyControl with the given criticality.
     *
     * @param criticality control criticality.
     */
    public PermissiveModifyControl(final boolean criticality) {
        super(OID, criticality, null);
    }
}

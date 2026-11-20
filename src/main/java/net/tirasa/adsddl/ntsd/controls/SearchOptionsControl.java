/*
 * Copyright (C) 2018 Tirasa (info@tirasa.net)
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
package net.tirasa.adsddl.ntsd.controls;

import java.nio.ByteBuffer;
import javax.naming.ldap.BasicControl;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;

/**
 * The LDAP_SERVER_SEARCH_OPTIONS_OID control is used to pass flags to the server to control various search behaviors.
 */
public class SearchOptionsControl extends BasicControl {

    private static final long serialVersionUID = -930993758829518418L;

    /**
     * LDAP_SERVER_SEARCH_OPTIONS_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.1340";

    /**
     * SERVER_SEARCH_FLAG_DOMAIN_SCOPE: 0x00000001
     * SERVER_SEARCH_FLAG_PHANTOM_ROOT: 0x00000002
     */
    private int flags = 0x00000001;

    /**
     * Constructor.
     */
    public SearchOptionsControl() {
        super(OID, true, null);
        this.value = berEncodedValue();
    }

    /**
     * Constructor.
     *
     * @param flags search option flags.
     */
    public SearchOptionsControl(final int flags) {
        super(OID, true, null);
        this.flags = flags;
        this.value = berEncodedValue();
    }

    /**
     * Sets search option flags.
     *
     * @param flags search option flags.
     * @return the current SearchOptionsControl instance.
     */
    public SearchOptionsControl setFlags(final int flags) {
        this.flags = flags;
        this.value = berEncodedValue();
        return this;
    }

    /**
     * BER encode the flags.
     *
     * @return flags BER encoded.
     */
    private byte[] berEncodedValue() {
        final byte[] trimmed = NumberFacility.leftTrim(NumberFacility.getBytes(flags));
        final ByteBuffer buff = ByteBuffer.allocate(4 + trimmed.length);
        buff.put((byte) 0x30); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        buff.put((byte) (2 + trimmed.length)); // size
        buff.put((byte) 0x02); // int tag
        buff.put((byte) trimmed.length); // int size
        buff.put(trimmed); // value
        return buff.array();
    }
}

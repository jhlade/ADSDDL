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
package cz.jhlade.adsddl.unit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import cz.jhlade.adsddl.controls.BerCodec;
import cz.jhlade.adsddl.controls.DirSyncResponse;
import cz.jhlade.adsddl.controls.ExtendedDNControl;
import cz.jhlade.adsddl.controls.PagedResultsResponse;
import cz.jhlade.adsddl.controls.PermissiveModifyControl;
import java.nio.charset.StandardCharsets;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.Control;
import org.junit.jupiter.api.Test;

public class ControlsBerTest {

    @Test
    public void dirSyncResponseDecode() {
        final byte[] cookie = "dirsync-cookie-payload-0123456789".getBytes(StandardCharsets.UTF_8);
        final byte[] encoded = BerCodec.encodeIntIntOctetStringSequence(1, 0, cookie, false);

        final Control[] responseControls = new Control[] {
            new BasicControl(DirSyncResponse.OID, false, encoded)
        };

        final DirSyncResponse decoded = DirSyncResponse.fromResponseControls(responseControls);
        assertNotNull(decoded);
        assertTrue(decoded.hasMoreResults());
        assertEquals(1, decoded.getFlag());
        assertEquals(0, decoded.getMaxReturnLength());
        assertArrayEquals(cookie, decoded.getCookie());

        // Last page (flag == 0)
        final byte[] lastPageBer = BerCodec.encodeIntIntOctetStringSequence(0, 0, cookie, true);
        final DirSyncResponse lastPage = DirSyncResponse.decode(lastPageBer);
        assertFalse(lastPage.hasMoreResults());
        assertArrayEquals(cookie, lastPage.getCookie());
    }

    @Test
    public void pagedResultsResponseDecode() {
        final byte[] pageCookie = new byte[] { 0x10, 0x20, 0x30, 0x40 };
        final byte[] ber = PagedResultsResponse.encodeRequestValue(250, pageCookie);

        final Control[] controls = new Control[] {
            new BasicControl(PagedResultsResponse.OID, false, ber)
        };

        final PagedResultsResponse resp = PagedResultsResponse.fromResponseControls(controls);
        assertNotNull(resp);
        assertEquals(250, resp.getEstimatedTotalSize());
        assertTrue(resp.hasMorePages());
        assertArrayEquals(pageCookie, resp.getCookie());

        // End of pages (empty cookie)
        final PagedResultsResponse endResp = PagedResultsResponse.decode(
                PagedResultsResponse.encodeRequestValue(0, new byte[0]));
        assertFalse(endResp.hasMorePages());
        assertEquals(0, endResp.getCookie().length);
    }

    @Test
    public void extendedDnAndPermissiveModifyControls() {
        final ExtendedDNControl extCtrl = new ExtendedDNControl(ExtendedDNControl.FORMAT_STANDARD_STRING);
        assertEquals(ExtendedDNControl.OID, extCtrl.getID());
        assertArrayEquals(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, extCtrl.getEncodedValue());

        final String rawDn = "<GUID=ab721a53-1e2f-11d0-9819-00aa0040529b>;"
                + "<SID=S-1-5-21-1835709989-2027683138-697581538-1139>;"
                + "CN=Jan Novak,OU=5A,OU=Zaci,DC=skola,DC=local";
        final ExtendedDNControl.ParsedExtendedDN parsed = ExtendedDNControl.ParsedExtendedDN.parse(rawDn);
        assertEquals("ab721a53-1e2f-11d0-9819-00aa0040529b", parsed.getGuid());
        assertEquals("S-1-5-21-1835709989-2027683138-697581538-1139", parsed.getSid());
        assertEquals("CN=Jan Novak,OU=5A,OU=Zaci,DC=skola,DC=local", parsed.getDistinguishedName());

        final PermissiveModifyControl permCtrl = new PermissiveModifyControl(false);
        assertEquals(PermissiveModifyControl.OID, permCtrl.getID());
        assertFalse(permCtrl.isCritical());
        assertNull(permCtrl.getEncodedValue());
    }
}

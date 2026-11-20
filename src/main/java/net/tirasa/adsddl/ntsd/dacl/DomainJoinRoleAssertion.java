/*
 * Copyright (C) 2018 VMware, Inc.
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
 /*
 * Copyright © 2018 VMware, Inc. All Rights Reserved.
 *
 * COPYING PERMISSION STATEMENT
 * SPDX-License-Identifier: Apache-2.0
 */
package net.tirasa.adsddl.ntsd.dacl;

import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import java.util.Arrays;
import java.util.List;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;

/**
 * Represents an {@linkplain AdRoleAssertion} which specifies the criteria required to join or remove computers
 * to/from an AD domain in a given container (& its children) without any restrictions. This includes the ability
 * to reset AD computer passwords, which is needed by some systems that manage domain joined computers.
 */
public class DomainJoinRoleAssertion extends AdRoleAssertion {

    /**
     * Schema GUID of "CN=Computer,CN=Schema,CN=Configuration" objects
     */
    protected static final String COMPUTER_SCHEMA_ID_GUID = AdSchemaGuid.CLASS_COMPUTER.getGuidString();

    /**
     * Schema GUID of "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration" extended right
     * (aka "reset password")
     */
    protected static final String RESET_PASSWORD_CR_GUID = AdExtendedRight.USER_FORCE_CHANGE_PASSWORD.getGuidString();

    /**
     * Create computer object applied to "This object and all descendant objects"
     */
    protected static final AceAssertion CREATE_COMPUTER = new AceAssertion(
            AceRights.parseValue(ObjectRight.CC.getValue()),
            AdSchemaGuid.CLASS_COMPUTER,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

    /**
     * DELETE_COMPUTER - Delete computer object applied to "This object and all descendant objects"
     */
    protected static final AceAssertion DELETE_COMPUTER = new AceAssertion(
            AceRights.parseValue(ObjectRight.DC.getValue()),
            AdSchemaGuid.CLASS_COMPUTER,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

    /**
     * LIST_CONTENTS - List contents applied to "This object and all descendant objects"
     */
    protected static final AceAssertion LIST_CONTENTS = new AceAssertion(
            AceRights.parseValue(ObjectRight.LC.getValue()),
            (AdSchemaGuid) null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

    /**
     * READ_PROPERTIES - Read All Properties applied at any of below scopes on target Organizational Unit
     * - This object only
     * - This object and all descendant objects
     * - All descendant objects
     */
    protected static final AceAssertion READ_PROPERTIES_ANY_SCOPE = new AceAssertion(
            AceRights.parseValue(ObjectRight.RP.getValue()));

    /**
     * READ_PROPERTIES - Read All Properties applied to "This object and all descendant objects"
     */
    protected static final AceAssertion READ_PROPERTIES = new AceAssertion(
            AceRights.parseValue(ObjectRight.RP.getValue()),
            (AdSchemaGuid) null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

    /**
     * WRITE_PROPERTIES_COMPUTER_OBJECTS - Write all propeties applied to "Descendant Computer Objects"
     */
    protected static final AceAssertion WRITE_PROPERTIES_COMPUTER_OBJECTS = new AceAssertion(
            AceRights.parseValue(ObjectRight.WP.getValue()),
            (AdSchemaGuid) null,
            AdSchemaGuid.CLASS_COMPUTER,
            AceFlag.CONTAINER_INHERIT_ACE,
            null);

    /**
     * WRITE_PROPERTIES - Write all propeties applied to "This object and all descendant objects"
     */
    protected static final AceAssertion WRITE_PROPERTIES = new AceAssertion(
            AceRights.parseValue(ObjectRight.WP.getValue()),
            (AdSchemaGuid) null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            null);

    /**
     * READ_PERMISSIONS - Read Permissions(a.k.a Read Control) applied to "This object and all descendant objects"
     */
    protected static final AceAssertion READ_PERMISSIONS = new AceAssertion(
            AceRights.parseValue(ObjectRight.RC.getValue()),
            (AdSchemaGuid) null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

    /**
     * RESET_PASSWORD - Permission to force reset password applied to "Descendant Computer Objects"
     */
    protected static final AceAssertion RESET_PASSWORD = new AceAssertion(
            AceRights.parseValue(ObjectRight.CR.getValue()),
            AdExtendedRight.USER_FORCE_CHANGE_PASSWORD,
            AdSchemaGuid.CLASS_COMPUTER,
            AceFlag.CONTAINER_INHERIT_ACE,
            null);


    protected static List<AceAssertion> domainJoinAssertions(boolean withMinimumRequiredPermissions) {

        if (withMinimumRequiredPermissions) {
            return Arrays.asList(
                    CREATE_COMPUTER,
                    DELETE_COMPUTER,
                    READ_PROPERTIES_ANY_SCOPE,
                    WRITE_PROPERTIES_COMPUTER_OBJECTS,
                    RESET_PASSWORD);
        }

        return Arrays.asList(CREATE_COMPUTER,
                DELETE_COMPUTER,
                LIST_CONTENTS,
                READ_PROPERTIES,
                WRITE_PROPERTIES,
                READ_PERMISSIONS,
                RESET_PASSWORD);
    }

    /**
     * DomainJoinRoleAssertion constructor
     *
     * @param principal
     * SID of the user or group
     * @param isGroup
     * whether the principal is a group
     * @param tokenGroups
     * list of token group SIDs which should be searched if the principal itself does not meet all the
     * criteria (when the principal is a user). May be null.
     * @param withMinimumRequiredPermissions
     * assert with minimum required join account permissions
     */
    public DomainJoinRoleAssertion(SID principal, boolean isGroup, List<SID> tokenGroups, boolean withMinimumRequiredPermissions) {
        super(domainJoinAssertions(withMinimumRequiredPermissions), principal, isGroup, tokenGroups);
    }

    /**
     * DomainJoinRoleAssertion constructor
     *
     * @param principal
     * SID of the user or group
     * @param isGroup
     * whether the principal is a group
     * @param tokenGroups
     * list of token group SIDs which should be searched if the principal itself does not meet all the
     * criteria (when the principal is a user). May be null.
     */
    public DomainJoinRoleAssertion(SID principal, boolean isGroup, List<SID> tokenGroups) {
        this(principal,isGroup,tokenGroups,false);
    }
}

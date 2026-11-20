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
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags.Flag;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;

/**
 * Represents an assertion that an {@code ACL} must contain an {@code ACE} (Access Control Entry) which meets the 
 * criteria within this class. The criteria are defined as properties of the ACE.<br>
 * <br>
 * Special interpretation of the 'excluded flag': If this flag is specified, and an ACE contains this flag, the ACE 
 * cannot be considered to fulfill the assertion.
 */
public class AceAssertion {

    /**
     * A single AceRight.
     */
    private AceRights aceRight;

    /**
     * One or more AceObjectFlags. May be null.
     */
    private AceObjectFlags aceObjectFlags;

    /**
     * Object type GUID. Must be set if {@code Flag.ACE_OBJECT_TYPE_PRESENT} is one of the AceObjectFlags; otherwise null.
     */
    private String objectType;

    /**
     * Inherited Object type GUID. Must be set if {@code Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT} is one of the AceObjectFlags;
     * otherwise null.
     */
    private String inheritedObjectType;

    /**
     * Single AceFlag that stipulates an ACE must contain it; may be null.
     */
    private AceFlag requiredFlag;

    /**
     * Single AceFlag that stipulates an ACE must NOT contain it; may be null.
     */
    private AceFlag excludedFlag;

    /**
     * AceAssertion constructor
     *
     * @param aceRight
     *            A single AceRight (e.g.: use {@code AceRights.parseValue(0x00000004)} if {@code AceRights.ObjectRight} enum does
     *            not contain desired right.) MUST be specified.
     */
    public AceAssertion(AceRights aceRight) {
        this.aceRight = aceRight;
    }

    /**
     * AceAssertion constructor
     *
     * @param aceRight
     *            A single AceRight (e.g.: use {@code AceRights.parseValue(0x00000004)} if {@code AceRights.ObjectRight} enum does
     *            not contain desired right.) MUST be specified.
     * @param aceObjFlags
     *            One or more {@code AceObjectFlags}, may be null.
     * @param objectType
     *            Object type GUID. Must be set if {@code Flag.ACE_OBJECT_TYPE_PRESENT} is in aceObjFlags
     * @param inheritedObjectType
     *            Inherited object type GUID. Must be set if {@code Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT} is in aceObjFlags
     * @param requiredFlag
     *            Single AceFlag that stipulates an ACE must contain it; may be null.
     * @param excludedFlag
     *            Single AceFlag that stipulates an ACE must NOT contain it; may be null.
     */
    public AceAssertion(AceRights aceRight, AceObjectFlags aceObjFlags, String objectType, String inheritedObjectType,
            AceFlag requiredFlag, AceFlag excludedFlag) {
        this.aceRight = aceRight;
        this.aceObjectFlags = aceObjFlags;
        this.objectType = objectType;
        this.inheritedObjectType = inheritedObjectType;
        this.requiredFlag = requiredFlag;
        this.excludedFlag = excludedFlag;
    }

    /**
     * AceAssertion constructor using catalog enums {@link AdExtendedRight} / {@link AdSchemaGuid}.
     *
     * @param aceRight ACE right.
     * @param extendedRight extended right for ObjectType (may be null).
     * @param inheritedObjectType inherited object class schema GUID (may be null).
     * @param requiredFlag required AceFlag (may be null).
     * @param excludedFlag excluded AceFlag (may be null).
     */
    public AceAssertion(
            final AceRights aceRight,
            final AdExtendedRight extendedRight,
            final AdSchemaGuid inheritedObjectType,
            final AceFlag requiredFlag,
            final AceFlag excludedFlag) {
        this(
                aceRight,
                buildObjectFlags(extendedRight != null, inheritedObjectType != null),
                extendedRight == null ? null : extendedRight.getGuidString(),
                inheritedObjectType == null ? null : inheritedObjectType.getGuidString(),
                requiredFlag,
                excludedFlag);
    }

    /**
     * AceAssertion constructor using {@link AdSchemaGuid} for ObjectType and InheritedObjectType.
     *
     * @param aceRight ACE right.
     * @param objectType schema GUID for ObjectType (may be null).
     * @param inheritedObjectType schema GUID for InheritedObjectType (may be null).
     * @param requiredFlag required AceFlag (may be null).
     * @param excludedFlag excluded AceFlag (may be null).
     */
    public AceAssertion(
            final AceRights aceRight,
            final AdSchemaGuid objectType,
            final AdSchemaGuid inheritedObjectType,
            final AceFlag requiredFlag,
            final AceFlag excludedFlag) {
        this(
                aceRight,
                buildObjectFlags(objectType != null, inheritedObjectType != null),
                objectType == null ? null : objectType.getGuidString(),
                inheritedObjectType == null ? null : inheritedObjectType.getGuidString(),
                requiredFlag,
                excludedFlag);
    }

    private static AceObjectFlags buildObjectFlags(final boolean hasObj, final boolean hasInh) {
        if (!hasObj && !hasInh) {
            return null;
        }
        final AceObjectFlags flags = new AceObjectFlags();
        if (hasObj) {
            flags.addFlag(Flag.ACE_OBJECT_TYPE_PRESENT);
        }
        if (hasInh) {
            flags.addFlag(Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT);
        }
        return flags;
    }

    /**
     * Gets the {@code AceRight} specifying the right of this assertion.
     *
     * @return AceRight object
     */
    public AceRights getAceRight() {
       return aceRight;
    }

    /**
     * Gets one or more {@code AceObjectFlags} of the assertion, may be null.
     *
     * @return AceObjectFlags object or null if none
     */
    public AceObjectFlags getObjectFlags() {
       return aceObjectFlags;
    }

    /**
     * Gets the object type GUID. Present only if {@code Flag.ACE_OBJECT_TYPE_PRESENT} is in {@link getObjectFlags}
     *
     * @return Object type GUID string or null if none
     */
    public String getObjectType() {
        return objectType;
    }

    /**
     * Gets the inherited object type GUID. Present only if {@code Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT} is in
     * {@link getObjectFlags}
     *
     * @return Inherited object type GUID string or null if none
     */
    public String getInheritedObjectType() {
        return inheritedObjectType;
    }

    /**
     * Gets single {@code AceFlag} that stipulates an ACE must contain it; may be null.
     *
     * @return Gets required flag
     */
    public AceFlag getRequiredFlag() {
        return requiredFlag;
    }

    /**
     * Gets single {@code AceFlag} that stipulates an ACE must NOT contain it; may be null.
     *
     * @return gets excluded flag
     */
    public AceFlag getExcludedFlag() {
        return excludedFlag;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = (int) (prime * result + ((aceObjectFlags == null) ? 0 : aceObjectFlags.asUInt()));
        result = (int) (prime * result + ((aceRight == null) ? 0 : aceRight.asUInt()));
        result = prime * result + ((inheritedObjectType == null) ? 0 : inheritedObjectType.hashCode());
        result = prime * result + ((objectType == null) ? 0 : objectType.hashCode());
        result = prime * result + ((requiredFlag == null) ? 0 : requiredFlag.hashCode());
        result = prime * result + ((excludedFlag == null) ? 0 : excludedFlag.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AceAssertion other = (AceAssertion) obj;

        if (aceObjectFlags == null) {
            if (other.aceObjectFlags != null) {
                return false;
            }
        } else if (other.aceObjectFlags == null) {
            return false;
        } else if (aceObjectFlags.asUInt() != other.aceObjectFlags.asUInt()) {
            return false;
        }
        if (aceRight == null) {
            if (other.aceRight != null) {
                return false;
            }
        } else if (other.aceRight == null) {
            return false;
        } else if (aceRight.asUInt() != other.aceRight.asUInt()) {
            return false;
        }
        if (inheritedObjectType == null) {
            if (other.inheritedObjectType != null) {
                return false;
            }
        } else if (!inheritedObjectType.equals(other.inheritedObjectType))
            return false;
        if (objectType == null) {
            if (other.objectType != null) {
                return false;
            }
        } else if (!objectType.equals(other.objectType)) {
            return false;
        }
        if (requiredFlag == null) {
            if (other.requiredFlag != null) {
                return false;
            }
        } else if (other.requiredFlag == null) {
            return false;
        } else if (requiredFlag.getValue() != other.requiredFlag.getValue()) {
            return false;
        }
        if (excludedFlag == null) {
            if (other.excludedFlag != null) {
                return false;
            }
        } else if (other.excludedFlag == null) {
            return false;
        } else if (excludedFlag.getValue() != other.excludedFlag.getValue()) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        String right = aceRight == null ? "null" : String.valueOf(aceRight.asUInt());
        String objFlags = aceObjectFlags == null ? "null" : String.valueOf(aceObjectFlags.asUInt());
        String reqFlag = requiredFlag == null ? "null" : requiredFlag.name();
        String exFlag = excludedFlag == null ? "null" : excludedFlag.name();

        return "AceAssertion [aceRight=" + right + getRightsAbbrevStringForToString() + ", aceObjectFlags=" + objFlags
                + ", objectType="
                + objectType
                + ", inheritedObjectType=" + inheritedObjectType + ", requiredFlag=" + reqFlag + ", excludedFlag="
                + exFlag + "]";
    }

    public String getRightsAbbrevStringForToString() {
        return "(" + getRightsAbbrevString() + ")";
    }

    public String getRightsAbbrevString() {
        if (aceRight == null) {
            return "null";
        }
        for (ObjectRight rightVal : AceRights.ObjectRight.values()) {
            if ((aceRight.asUInt() & rightVal.getValue()) == rightVal.getValue()) {
                return rightVal.name();
            }
        }
        if (aceRight.asUInt() == 0x00000008L) {
            return "SW";
        }
        return "?";
    }
}

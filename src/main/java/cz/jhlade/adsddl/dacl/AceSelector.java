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
package cz.jhlade.adsddl.dacl;

import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import java.util.Arrays;
import java.util.function.Predicate;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;

/**
 * Composable, zero-allocation predicates for querying and filtering {@link ACE} entries in an {@code ACL}.
 */
public final class AceSelector {

    private AceSelector() {
    }

    /**
     * Matches ACEs belonging to the given trustee {@link SID}.
     *
     * @param sid trustee SID.
     * @return predicate.
     */
    public static Predicate<ACE> hasSid(final SID sid) {
        return ace -> ace != null && sid != null && sid.equals(ace.getSid());
    }

    /**
     * Matches ACEs whose type is one of the allowed types ({@code ACCESS_ALLOWED_ACE_TYPE} or
     * {@code ACCESS_ALLOWED_OBJECT_ACE_TYPE}).
     *
     * @return predicate.
     */
    public static Predicate<ACE> isAllow() {
        return ace -> ace != null
                && (ace.getType() == AceType.ACCESS_ALLOWED_ACE_TYPE
                || ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
    }

    /**
     * Matches ACEs whose type is one of the denied types ({@code ACCESS_DENIED_ACE_TYPE} or
     * {@code ACCESS_DENIED_OBJECT_ACE_TYPE}).
     *
     * @return predicate.
     */
    public static Predicate<ACE> isDeny() {
        return ace -> ace != null
                && (ace.getType() == AceType.ACCESS_DENIED_ACE_TYPE
                || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE);
    }

    /**
     * Matches explicit (non-inherited) ACEs (those without {@link AceFlag#INHERITED_ACE}).
     *
     * @return predicate.
     */
    public static Predicate<ACE> isExplicit() {
        return ace -> ace != null && !ace.getFlags().contains(AceFlag.INHERITED_ACE);
    }

    /**
     * Matches inherited ACEs (those with {@link AceFlag#INHERITED_ACE}).
     *
     * @return predicate.
     */
    public static Predicate<ACE> isInherited() {
        return ace -> ace != null && ace.getFlags().contains(AceFlag.INHERITED_ACE);
    }

    /**
     * Matches ACEs whose rights mask contains all of the specified {@link ObjectRight} bits.
     *
     * @param requiredRights required rights.
     * @return predicate.
     */
    public static Predicate<ACE> hasRights(final ObjectRight... requiredRights) {
        long mask = 0;
        if (requiredRights != null) {
            for (ObjectRight r : requiredRights) {
                if (r != null) {
                    mask |= (r.getValue() & 0xFFFFFFFFL);
                }
            }
        }
        final long requiredMask = mask;
        return ace -> ace != null
                && ace.getRights() != null
                && (ace.getRights().asUInt() & requiredMask) == requiredMask;
    }

    /**
     * Matches ACEs whose rights mask contains at least one of the specified {@link ObjectRight} bits.
     *
     * @param candidateRights candidate rights.
     * @return predicate.
     */
    public static Predicate<ACE> hasAnyRight(final ObjectRight... candidateRights) {
        long mask = 0;
        if (candidateRights != null) {
            for (ObjectRight r : candidateRights) {
                if (r != null) {
                    mask |= (r.getValue() & 0xFFFFFFFFL);
                }
            }
        }
        final long anyMask = mask;
        return ace -> ace != null
                && ace.getRights() != null
                && (ace.getRights().asUInt() & anyMask) != 0;
    }

    /**
     * Matches Object ACEs targeting the specified 16-byte {@code ObjectType} GUID.
     *
     * @param objectTypeBytes 16-byte binary GUID.
     * @return predicate.
     */
    public static Predicate<ACE> hasObjectType(final byte[] objectTypeBytes) {
        final byte[] target = objectTypeBytes == null ? null : Arrays.copyOf(objectTypeBytes, objectTypeBytes.length);
        return ace -> {
            if (ace == null) {
                return false;
            }
            if (target == null) {
                return ace.getObjectType() == null;
            }
            return ace.getObjectFlags() != null
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                    && Arrays.equals(ace.getObjectType(), target);
        };
    }

    /**
     * Matches Object ACEs targeting the specified string {@code ObjectType} GUID without allocating a String on ACE.
     *
     * @param guidString 36-char GUID string.
     * @return predicate.
     */
    public static Predicate<ACE> hasObjectType(final String guidString) {
        return ace -> ace != null
                && ace.getObjectFlags() != null
                && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                && GUID.equals(ace.getObjectType(), guidString);
    }

    /**
     * Matches Object ACEs targeting the specified {@link AdExtendedRight}.
     *
     * @param extendedRight extended right.
     * @return predicate.
     */
    public static Predicate<ACE> hasExtendedRight(final AdExtendedRight extendedRight) {
        return ace -> ace != null
                && extendedRight != null
                && ace.getRights() != null
                && (ace.getRights().asUInt() & ObjectRight.CR.getValue()) != 0
                && ace.getObjectFlags() != null
                && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                && extendedRight.matches(ace.getObjectType());
    }

    /**
     * Matches Object ACEs targeting the specified {@link AdSchemaGuid} in {@code ObjectType}.
     *
     * @param schemaGuid schema class, attribute, or property set GUID.
     * @return predicate.
     */
    public static Predicate<ACE> hasObjectType(final AdSchemaGuid schemaGuid) {
        return ace -> ace != null
                && schemaGuid != null
                && ace.getObjectFlags() != null
                && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
                && schemaGuid.matches(ace.getObjectType());
    }

    /**
     * Matches Object ACEs targeting the specified {@link AdSchemaGuid} in {@code InheritedObjectType}.
     *
     * @param schemaGuid inherited object class schema GUID.
     * @return predicate.
     */
    public static Predicate<ACE> hasInheritedObjectType(final AdSchemaGuid schemaGuid) {
        return ace -> ace != null
                && schemaGuid != null
                && ace.getObjectFlags() != null
                && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)
                && schemaGuid.matches(ace.getInheritedObjectType());
    }
}

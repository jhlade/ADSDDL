package cz.jhlade.adsddl.dacl;

import cz.jhlade.adsddl.data.AdExtendedRight;
import cz.jhlade.adsddl.data.AdSchemaGuid;
import cz.jhlade.adsddl.data.WellKnownSid;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;

/**
 * Fluent builder for constructing valid standard and object-specific {@link ACE} instances.
 * <p>
 * Automatically upgrades {@code ACCESS_ALLOWED_ACE_TYPE} to {@code ACCESS_ALLOWED_OBJECT_ACE_TYPE}
 * (and {@code ACCESS_DENIED_ACE_TYPE} to {@code ACCESS_DENIED_OBJECT_ACE_TYPE}) whenever an
 * {@code ObjectType} or {@code InheritedObjectType} GUID is set, and synchronizes {@code AceObjectFlags}.
 * </p>
 */
public final class AceBuilder {

    private AceType type;

    private final List<AceFlag> flags = new ArrayList<>(4);

    private final AceRights rights = new AceRights();

    private byte[] objectType;

    private byte[] inheritedObjectType;

    private SID sid;

    private byte[] applicationData;

    private AceBuilder(final AceType type) {
        this.type = type;
    }

    /**
     * Starts building an Access-Allowed ACE for the given trustee SID.
     *
     * @param sid trustee SID.
     * @return builder instance.
     */
    public static AceBuilder allow(final SID sid) {
        return new AceBuilder(AceType.ACCESS_ALLOWED_ACE_TYPE).forSid(sid);
    }

    /**
     * Starts building an Access-Allowed ACE for a well-known SID.
     *
     * @param wellKnownSid universal/built-in well-known SID.
     * @return builder instance.
     */
    public static AceBuilder allow(final WellKnownSid wellKnownSid) {
        return new AceBuilder(AceType.ACCESS_ALLOWED_ACE_TYPE).forSid(wellKnownSid.toSid());
    }

    /**
     * Starts building an Access-Denied ACE for the given trustee SID.
     *
     * @param sid trustee SID.
     * @return builder instance.
     */
    public static AceBuilder deny(final SID sid) {
        return new AceBuilder(AceType.ACCESS_DENIED_ACE_TYPE).forSid(sid);
    }

    /**
     * Starts building an Access-Denied ACE for a well-known SID.
     *
     * @param wellKnownSid universal/built-in well-known SID.
     * @return builder instance.
     */
    public static AceBuilder deny(final WellKnownSid wellKnownSid) {
        return new AceBuilder(AceType.ACCESS_DENIED_ACE_TYPE).forSid(wellKnownSid.toSid());
    }

    /**
     * Starts building a System-Audit ACE (for SACL) for the given trustee SID.
     *
     * @param sid trustee SID.
     * @return builder instance.
     */
    public static AceBuilder audit(final SID sid) {
        return new AceBuilder(AceType.SYSTEM_AUDIT_ACE_TYPE).forSid(sid);
    }

    /**
     * Sets the trustee SID.
     *
     * @param trusteeSid trustee SID.
     * @return this builder.
     */
    public AceBuilder forSid(final SID trusteeSid) {
        this.sid = trusteeSid;
        return this;
    }

    /**
     * Sets the trustee SID from its string representation (e.g. {@code "S-1-5-10"}).
     *
     * @param sidString SID string.
     * @return this builder.
     */
    public AceBuilder forSid(final String sidString) {
        this.sid = SID.parse(sidString);
        return this;
    }

    /**
     * Sets the trustee SID from a {@link WellKnownSid} and optional domain SID.
     *
     * @param wellKnownSid well-known SID.
     * @param domainSid domain SID (required if {@code wellKnownSid.isDomainRelative()}).
     * @return this builder.
     */
    public AceBuilder forSid(final WellKnownSid wellKnownSid, final SID domainSid) {
        this.sid = wellKnownSid.toSid(domainSid);
        return this;
    }

    /**
     * Adds one or more standard {@link ObjectRight} permissions.
     *
     * @param objectRights rights to add.
     * @return this builder.
     */
    public AceBuilder withRights(final ObjectRight... objectRights) {
        if (objectRights != null) {
            for (ObjectRight right : objectRights) {
                rights.addObjectRight(right);
            }
        }
        return this;
    }

    /**
     * Adds a raw 32-bit access mask to the ACE rights.
     *
     * @param rawMask 32-bit access mask.
     * @return this builder.
     */
    public AceBuilder withRawRights(final int rawMask) {
        final long combined = rights.asUInt() | (rawMask & 0xFFFFFFFFL);
        final AceRights parsed = AceRights.parseValue((int) combined);
        rights.getObjectRights().clear();
        rights.getObjectRights().addAll(parsed.getObjectRights());
        rights.setOthers(parsed.getOthers());
        return this;
    }

    /**
     * Configures this ACE for an {@link AdExtendedRight} (automatically adds {@link ObjectRight#CR}
     * and sets {@code ObjectType} to the extended right's GUID).
     *
     * @param extendedRight extended right.
     * @return this builder.
     */
    public AceBuilder withExtendedRight(final AdExtendedRight extendedRight) {
        rights.addObjectRight(ObjectRight.CR);
        return withObjectType(extendedRight.getGuidBytes());
    }

    /**
     * Sets the {@code ObjectType} GUID from an {@link AdSchemaGuid}.
     *
     * @param schemaGuid schema class, attribute, or property set GUID.
     * @return this builder.
     */
    public AceBuilder withObjectType(final AdSchemaGuid schemaGuid) {
        return withObjectType(schemaGuid == null ? (byte[]) null : schemaGuid.getGuidBytes());
    }

    /**
     * Sets the {@code ObjectType} GUID from a string GUID.
     *
     * @param guidString 36-char GUID string.
     * @return this builder.
     */
    public AceBuilder withObjectType(final String guidString) {
        return withObjectType(guidString == null ? null : GUID.getGuidAsByteArray(guidString));
    }

    /**
     * Sets the 16-byte binary {@code ObjectType} GUID.
     *
     * @param guidBytes 16-byte binary GUID.
     * @return this builder.
     */
    public AceBuilder withObjectType(final byte[] guidBytes) {
        if (guidBytes == null || guidBytes.length == 0) {
            this.objectType = null;
        } else {
            if (guidBytes.length != 16) {
                throw new IllegalArgumentException("ObjectType GUID must be 16 bytes");
            }
            this.objectType = Arrays.copyOf(guidBytes, 16);
            upgradeToObjectAceType();
        }
        return this;
    }

    /**
     * Sets the {@code InheritedObjectType} GUID (restricting which child object class inherits this ACE).
     *
     * @param schemaGuid child object class schema GUID (e.g. {@link AdSchemaGuid#CLASS_USER}).
     * @return this builder.
     */
    public AceBuilder withInheritedObjectType(final AdSchemaGuid schemaGuid) {
        return withInheritedObjectType(schemaGuid == null ? (byte[]) null : schemaGuid.getGuidBytes());
    }

    /**
     * Sets the {@code InheritedObjectType} GUID from a string GUID.
     *
     * @param guidString 36-char GUID string.
     * @return this builder.
     */
    public AceBuilder withInheritedObjectType(final String guidString) {
        return withInheritedObjectType(guidString == null ? null : GUID.getGuidAsByteArray(guidString));
    }

    /**
     * Sets the 16-byte binary {@code InheritedObjectType} GUID.
     *
     * @param guidBytes 16-byte binary GUID.
     * @return this builder.
     */
    public AceBuilder withInheritedObjectType(final byte[] guidBytes) {
        if (guidBytes == null || guidBytes.length == 0) {
            this.inheritedObjectType = null;
        } else {
            if (guidBytes.length != 16) {
                throw new IllegalArgumentException("InheritedObjectType GUID must be 16 bytes");
            }
            this.inheritedObjectType = Arrays.copyOf(guidBytes, 16);
            upgradeToObjectAceType();
        }
        return this;
    }

    /**
     * Adds one or more {@link AceFlag} flags.
     *
     * @param aceFlags flags to add.
     * @return this builder.
     */
    public AceBuilder withFlags(final AceFlag... aceFlags) {
        if (aceFlags != null) {
            for (AceFlag flag : aceFlags) {
                if (flag != null && !flags.contains(flag)) {
                    flags.add(flag);
                }
            }
        }
        return this;
    }

    /**
     * Applies this ACE to "This object and all descendant objects" ({@link AceFlag#CONTAINER_INHERIT_ACE}).
     *
     * @return this builder.
     */
    public AceBuilder applyToThisAndDescendants() {
        flags.remove(AceFlag.INHERIT_ONLY_ACE);
        return withFlags(AceFlag.CONTAINER_INHERIT_ACE);
    }

    /**
     * Applies this ACE to "Descendant objects only"
     * ({@link AceFlag#CONTAINER_INHERIT_ACE} + {@link AceFlag#INHERIT_ONLY_ACE}), optionally scoped to a specific
     * child object class (e.g. {@link AdSchemaGuid#CLASS_USER} or {@link AdSchemaGuid#CLASS_COMPUTER}).
     *
     * @param descendantClass target child class GUID, or {@code null} for all descendant objects.
     * @return this builder.
     */
    public AceBuilder applyToDescendantsOnly(final AdSchemaGuid descendantClass) {
        withFlags(AceFlag.CONTAINER_INHERIT_ACE, AceFlag.INHERIT_ONLY_ACE);
        if (descendantClass != null) {
            withInheritedObjectType(descendantClass);
        }
        return this;
    }

    /**
     * Sets optional application data for callback ACEs.
     *
     * @param appData application data.
     * @return this builder.
     */
    public AceBuilder withApplicationData(final byte[] appData) {
        this.applicationData = appData;
        return this;
    }

    private void upgradeToObjectAceType() {
        if (type == AceType.ACCESS_ALLOWED_ACE_TYPE) {
            type = AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;
        } else if (type == AceType.ACCESS_DENIED_ACE_TYPE) {
            type = AceType.ACCESS_DENIED_OBJECT_ACE_TYPE;
        } else if (type == AceType.SYSTEM_AUDIT_ACE_TYPE) {
            type = AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE;
        } else if (type == AceType.SYSTEM_ALARM_ACE_TYPE) {
            type = AceType.SYSTEM_ALARM_OBJECT_ACE_TYPE;
        }
    }

    /**
     * Builds the configured {@link ACE} instance.
     *
     * @return new {@link ACE} instance.
     */
    public ACE build() {
        if (sid == null) {
            throw new IllegalStateException("ACE requires a non-null trustee SID");
        }
        if (objectType != null || inheritedObjectType != null) {
            upgradeToObjectAceType();
        }
        final ACE ace = ACE.newInstance(type);
        ace.setFlags(flags);
        final AceRights aceRights = AceRights.parseValue((int) rights.asUInt());
        ace.setRights(aceRights);
        if (objectType != null) {
            ace.setObjectType(objectType);
        }
        if (inheritedObjectType != null) {
            ace.setInheritedObjectType(inheritedObjectType);
        }
        ace.setSid(sid);
        if (applicationData != null) {
            ace.setApplicationData(applicationData);
        }
        return ace;
    }
}

/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
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
package net.tirasa.adsddl.ntsd;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.AdsddlLogger;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;

/**
 * An access control entry (ACE) is used to encode the user rights afforded to a principal, either a user or group. This
 * is generally done by combining an ACCESS_MASK and the SID of the principal.
 */
public class ACE {

    /**
     * Logger.
     */
    protected static final AdsddlLogger LOG = AdsddlLogger.getLogger(ACE.class);

    /**
     * @see AceType
     */
    private AceType type;

    /**
     * @see AceFlag
     */
    private List<AceFlag> flags = new ArrayList<>();

    /**
     * @see AceRights
     */
    private AceRights rights;

    /**
     * @see AceObjectFlags
     */
    private AceObjectFlags objectFlags;

    /**
     * A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object.
     */
    private byte[] objectType;

    /**
     * A GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
     */
    private byte[] inheritedObjectType;

    /**
     * Optional application data.
     */
    private byte[] applicationData;

    /**
     * The SID of a trustee.
     */
    private SID sid;

    /**
     * Default constructor.
     */
    public ACE() {
    }

    /**
     * Creates a new ACE instance.
     *
     * @param type ACE type.
     * @return ACE.
     */
    public static ACE newInstance(final AceType type) {
        final ACE ace = new ACE();
        ace.setType(type);
        return ace;
    }

    /**
     * Checks whether the given AceType uses an Object-specific ACE wire structure.
     *
     * @param type ACE type.
     * @return true if Object ACE type.
     */
    public static boolean isObjectAceType(final AceType type) {
        return type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                || type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                || type == AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
                || type == AceType.SYSTEM_ALARM_OBJECT_ACE_TYPE
                || type == AceType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                || type == AceType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
                || type == AceType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
                || type == AceType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE;
    }

    /**
     * Load the ACE from the byte buffer returning the next byte position in the buffer.
     *
     * @param buff source byte buffer.
     * @param start start loading byte position.
     * @return next byte position after this ACE.
     */
    int parse(final ByteBuffer buff, final int start) {
        int pos = start;

        type = AceType.parseValue(buff.get(pos));
        flags = AceFlag.parseValue(buff.get(pos + 1));
        int size = ((buff.get(pos + 3) & 0xFF) << 8) | (buff.get(pos + 2) & 0xFF);

        pos += 4;
        int rawRights = (buff.get(pos) & 0xFF)
                | ((buff.get(pos + 1) & 0xFF) << 8)
                | ((buff.get(pos + 2) & 0xFF) << 16)
                | ((buff.get(pos + 3) & 0xFF) << 24);
        rights = AceRights.parseValue(rawRights);
        pos += 4;

        if (isObjectAceType(type)) {
            int rawObjFlags = (buff.get(pos) & 0xFF)
                    | ((buff.get(pos + 1) & 0xFF) << 8)
                    | ((buff.get(pos + 2) & 0xFF) << 16)
                    | ((buff.get(pos + 3) & 0xFF) << 24);
            objectFlags = AceObjectFlags.parseValue(rawObjFlags);
            pos += 4;

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                objectType = new byte[16];
                for (int i = 0; i < 16; i++) {
                    objectType[i] = buff.get(pos++);
                }
            }

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                inheritedObjectType = new byte[16];
                for (int i = 0; i < 16; i++) {
                    inheritedObjectType[i] = buff.get(pos++);
                }
            }
        }

        sid = new SID();
        pos = sid.parse(buff, pos);

        int endPos = start + size;
        if (endPos > pos) {
            applicationData = new byte[endPos - pos];
            for (int i = 0; i < applicationData.length; i++) {
                applicationData[i] = buff.get(pos++);
            }
        } else {
            applicationData = null;
        }

        return endPos;
    }

    /**
     * Load the ACE from the buffer returning the last ACE segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    int parse(final IntBuffer buff, final int start) {
        int pos = start;

        byte[] bytes = NumberFacility.getBytes(buff.get(pos));
        type = AceType.parseValue(bytes[0]);
        flags = AceFlag.parseValue(bytes[1]);

        int size = NumberFacility.getInt(bytes[3], bytes[2]);

        pos++;
        rights = AceRights.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

        if (isObjectAceType(type)) {
            pos++;
            objectFlags = AceObjectFlags.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                objectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, objectType, j * 4, 4);
                }
            }

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                inheritedObjectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, inheritedObjectType, j * 4, 4);
                }
            }
        }

        pos++;
        sid = new SID();
        pos = sid.parse(buff, pos);

        int lastPos = start + (size / 4) - 1;
        if (lastPos > pos) {
            applicationData = new byte[4 * (lastPos - pos)];
            int index = 0;
            while (pos < lastPos) {
                pos++;
                System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, applicationData, index, 4);
                index += 4;
            }
        } else {
            applicationData = null;
        }

        return pos;
    }

    /**
     * Gets ACE type.
     *
     * @see AceType
     * @return ACE type.
     */
    public AceType getType() {
        return type;
    }

    /**
     * Gets ACE flags.
     *
     * @see AceFlag
     * @return ACE flags; empty list if no flag has been specified.
     */
    public List<AceFlag> getFlags() {
        if (this.flags == null) {
            this.flags = new ArrayList<>();
        }
        return this.flags;
    }

    /**
     * Optional application data. The size of the application data is determined by the AceSize field.
     *
     * @return application data; null if not available.
     */
    public byte[] getApplicationData() {
        return this.applicationData == null || this.applicationData.length == 0
                ? null
                : Arrays.copyOf(this.applicationData, this.applicationData.length);
    }

    /**
     * Sets application data.
     *
     * @param applicationData application data.
     */
    public void setApplicationData(final byte[] applicationData) {
        this.applicationData = applicationData == null || applicationData.length == 0
                ? null
                : Arrays.copyOf(applicationData, applicationData.length);
    }

    /**
     * An ACCESS_MASK that specifies the user rights allowed by this ACE.
     *
     * @see AceRights
     * @return ACE rights.
     */
    public AceRights getRights() {
        return rights;
    }

    /**
     * A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
     * InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
     *
     * @see AceObjectFlags
     *
     * @return Flags.
     */
    public AceObjectFlags getObjectFlags() {
        return objectFlags;
    }

    /**
     * A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object. The purpose
     * of this GUID depends on the user rights specified in the Mask field. This field is valid only if the ACE
     * _OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise, the ObjectType field is ignored. For information
     * on access rights and for a mapping of the control access rights to the corresponding GUID value that identifies
     * each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
     *
     * ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set in an ACE with any
     * ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not find an appropriate GUID, then that ACE
     * will be ignored. For more information on access checks and object access, see [MS-ADTS] section 5.1.3.3.3.
     *
     * @return ObjectType; null if not available.
     */
    public byte[] getObjectType() {
        return this.objectType == null || this.objectType.length == 0
                ? null
                : Arrays.copyOf(this.objectType, this.objectType.length);
    }

    /**
     * A GUID (16 bytes) that identifies the type of child object that can inherit the ACE. Inheritance is also
     * controlled by the inheritance flags in the ACE_HEADER, as well as by any protection against inheritance placed on
     * the child objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags
     * member. Otherwise, the InheritedObjectType field is ignored.
     *
     * @return InheritedObjectType; null if not available.
     */
    public byte[] getInheritedObjectType() {
        return this.inheritedObjectType == null || this.inheritedObjectType.length == 0
                ? null
                : Arrays.copyOf(this.inheritedObjectType, this.inheritedObjectType.length);
    }

    /**
     * The SID of a trustee. The length of the SID MUST be a multiple of 4.
     *
     * @see SID
     * @return SID of the trustee.
     */
    public SID getSid() {
        return sid;
    }

    /**
     * An unsigned 16-bit integer that specifies the size, in bytes, of the ACE. The AceSize field can be greater than
     * the sum of the individual fields, but MUST be a multiple of 4 to ensure alignment on a DWORD boundary. In cases
     * where the AceSize field encompasses additional data for the callback ACEs types, that data is
     * implementation-specific. Otherwise, this additional data is not interpreted and MUST be ignored.
     *
     * @return ACE size (always a multiple of 4 bytes).
     */
    public int getSize() {
        final boolean isObj = isObjectAceType(type);
        final boolean hasObjType = isObj && objectType != null && objectType.length == 16;
        final boolean hasInhObjType = isObj && inheritedObjectType != null && inheritedObjectType.length == 16;
        final int appDataLen = applicationData == null ? 0 : (applicationData.length + 3) & ~3;
        return 8 + (isObj ? 4 : 0)
                + (hasObjType ? 16 : 0)
                + (hasInhObjType ? 16 : 0)
                + (sid == null ? 0 : sid.getSize())
                + appDataLen;
    }

    /**
     * Sets ACE type.
     *
     * @param type ACE type.
     * @see AceType
     */
    public void setType(final AceType type) {
        this.type = type;
    }

    /**
     * Adds ACE flag.
     *
     * @param flag ACE flag.
     * @see AceFlag
     */
    public void addFlag(final AceFlag flag) {
        if (this.flags == null) {
            this.flags = new ArrayList<>();
        }
        if (flag != null && !this.flags.contains(flag)) {
            this.flags.add(flag);
        }
    }

    /**
     * Removes ACE flag.
     *
     * @param flag ACE flag to remove.
     * @return true if the flag was present and removed.
     * @see AceFlag
     */
    public boolean removeFlag(final AceFlag flag) {
        return this.flags != null && this.flags.remove(flag);
    }

    /**
     * Sets ACE flags list.
     *
     * @param flags list of ACE flags.
     * @see AceFlag
     */
    public void setFlags(final List<AceFlag> flags) {
        this.flags = flags == null ? new ArrayList<>() : new ArrayList<>(flags);
    }

    /**
     * Sets ACE rights.
     *
     * @param rights ACE rights.
     * @see AceRights
     */
    public void setRights(final AceRights rights) {
        this.rights = rights;
    }

    /**
     * Sets object flags.
     *
     * @param objectFlags ACE object flags.
     * @see AceObjectFlags
     */
    public void setObjectFlags(final AceObjectFlags objectFlags) {
        this.objectFlags = objectFlags;
    }

    /**
     * Sets object type, a GUID (16 bytes) that identifies a property set, property, extended right, or type of child
     * object. Automatically updates {@link AceObjectFlags} accordingly.
     *
     * @param objectType ACE object type (16 bytes) or null.
     */
    public void setObjectType(final byte[] objectType) {
        if (objectType == null || objectType.length == 0) {
            this.objectType = null;
            if (this.objectFlags != null) {
                this.objectFlags.getFlags().remove(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT);
            }
        } else {
            if (objectType.length != 16) {
                throw new IllegalArgumentException("ObjectType GUID must be 16 bytes");
            }
            this.objectType = Arrays.copyOf(objectType, 16);
            if (this.objectFlags == null) {
                this.objectFlags = new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT);
            } else {
                this.objectFlags.addFlag(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT);
            }
        }
    }

    /**
     * Sets inherited object type, a GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
     * Automatically updates {@link AceObjectFlags} accordingly.
     *
     * @param inheritedObjectType Inherited object type (16 bytes) or null.
     */
    public void setInheritedObjectType(final byte[] inheritedObjectType) {
        if (inheritedObjectType == null || inheritedObjectType.length == 0) {
            this.inheritedObjectType = null;
            if (this.objectFlags != null) {
                this.objectFlags.getFlags().remove(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT);
            }
        } else {
            if (inheritedObjectType.length != 16) {
                throw new IllegalArgumentException("InheritedObjectType GUID must be 16 bytes");
            }
            this.inheritedObjectType = Arrays.copyOf(inheritedObjectType, 16);
            if (this.objectFlags == null) {
                this.objectFlags = new AceObjectFlags(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT);
            } else {
                this.objectFlags.addFlag(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT);
            }
        }
    }

    /**
     * Sets the SID of a trustee.
     *
     * @param sid SID of the trustee.
     * @see SID
     */
    public void setSid(final SID sid) {
        this.sid = sid;
    }

    private int computeEffectiveObjectFlagsMask() {
        int mask = objectFlags == null ? 0 : (int) objectFlags.getOthers();
        if (objectType != null && objectType.length == 16) {
            mask |= AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT.getValue();
        }
        if (inheritedObjectType != null && inheritedObjectType.length == 16) {
            mask |= AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT.getValue();
        }
        return mask;
    }

    /**
     * Writes this ACE directly into a little-endian ByteBuffer without intermediate array allocations.
     * Ensures wire format consistency between AceType, AceObjectFlags, ObjectType/InheritedObjectType GUIDs,
     * and 4-byte DWORD padding.
     *
     * @param buff target little-endian ByteBuffer.
     */
    void writeTo(final ByteBuffer buff) {
        final int size = getSize();

        buff.put(type == null ? AceType.UNEXPECTED.getValue() : type.getValue());

        byte flagSRC = 0x00;
        final List<AceFlag> fls = getFlags();
        for (int i = 0, n = fls.size(); i < n; i++) {
            flagSRC |= fls.get(i).getValue();
        }
        buff.put(flagSRC);

        buff.putShort((short) size);
        buff.putInt(rights == null ? 0 : (int) rights.asUInt());

        if (isObjectAceType(type)) {
            buff.putInt(computeEffectiveObjectFlagsMask());
            if (objectType != null && objectType.length == 16) {
                buff.put(objectType);
            }
            if (inheritedObjectType != null && inheritedObjectType.length == 16) {
                buff.put(inheritedObjectType);
            }
        }
        if (sid != null) {
            sid.writeTo(buff);
        }
        if (applicationData != null && applicationData.length > 0) {
            buff.put(applicationData);
            final int rem = applicationData.length & 3;
            if (rem != 0) {
                for (int p = 4 - rem; p > 0; p--) {
                    buff.put((byte) 0x00);
                }
            }
        }
    }

    /**
     * Serializes to byte array.
     *
     * @return serialized ACE.
     */
    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(getSize()).order(ByteOrder.LITTLE_ENDIAN);
        writeTo(buff);
        return buff.array();
    }

    /**
     * {@inheritDoc }
     *
     * @param ace ACE to be compared with.
     * @return <tt>true</tt> if equals; <tt>false</tt> otherwise.
     */
    @Override
    public boolean equals(final Object ace) {
        if (this == ace) {
            return true;
        }
        if (!(ace instanceof ACE)) {
            return false;
        }

        final ACE ext = (ACE) ace;

        if (getSize() != ext.getSize()) {
            LOG.debug("Different size");
            return false;
        }

        if (getType() != ext.getType()) {
            LOG.debug("Different type");
            return false;
        }

        if (!Arrays.equals(this.applicationData, ext.applicationData)) {
            LOG.debug("Different application data");
            return false;
        }

        if (!Objects.equals(getSid(), ext.getSid())) {
            LOG.debug("Different SID");
            return false;
        }

        if ((getObjectFlags() == null && ext.getObjectFlags() != null)
                || (getObjectFlags() != null && ext.getObjectFlags() == null)
                || (getObjectFlags() != null && ext.getObjectFlags() != null
                && getObjectFlags().asUInt() != ext.getObjectFlags().asUInt())) {
            LOG.debug("Different object flags");
            return false;
        }

        if (!Arrays.equals(this.objectType, ext.objectType)) {
            LOG.debug("Different object type");
            return false;
        }

        if (!Arrays.equals(this.inheritedObjectType, ext.inheritedObjectType)) {
            LOG.debug("Different inherited object type");
            return false;
        }

        final long thisRights = getRights() == null ? 0 : getRights().asUInt();
        final long extRights = ext.getRights() == null ? 0 : ext.getRights().asUInt();
        if (thisRights != extRights) {
            LOG.debug("Different rights");
            return false;
        }

        return new HashSet<>(getFlags()).equals(new HashSet<>(ext.getFlags()));
    }

    /**
     * Serializes to string.
     *
     * @return serialized ACE.
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();
        bld.append('(');
        bld.append(type == null ? "" : type.toString());
        bld.append(';');

        for (AceFlag flag : getFlags()) {
            bld.append(flag);
        }

        bld.append(';');

        if (rights != null) {
            for (AceRights.ObjectRight right : rights.getObjectRights()) {
                bld.append(right.name());
            }

            if (rights.getOthers() != 0) {
                bld.append('[');
                bld.append(rights.getOthers());
                bld.append(']');
            }
        }

        bld.append(';');

        if (objectType != null) {
            bld.append(GUID.getGuidAsString(objectType));
        }

        bld.append(';');

        if (inheritedObjectType != null) {
            bld.append(GUID.getGuidAsString(inheritedObjectType));
        }

        bld.append(';');

        if (sid != null) {
            bld.append(sid.toString());
        }

        bld.append(')');

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     *
     * @return hashcode.
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.type);
        hash = 53 * hash + new HashSet<>(getFlags()).hashCode();
        hash = 53 * hash + (this.rights == null ? 0 : Long.hashCode(this.rights.asUInt()));
        hash = 53 * hash + (this.objectFlags == null ? 0 : Long.hashCode(this.objectFlags.asUInt()));
        hash = 53 * hash + Arrays.hashCode(this.objectType);
        hash = 53 * hash + Arrays.hashCode(this.inheritedObjectType);
        hash = 53 * hash + Arrays.hashCode(this.applicationData);
        hash = 53 * hash + Objects.hashCode(this.sid);
        return hash;
    }

}

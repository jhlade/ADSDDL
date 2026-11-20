<!--

    Copyright (C) 2015 Tirasa (info@tirasa.net)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->
# ADSDDL
Active Directory and Samba 4 `nTSecurityDescriptor` parser, evaluator, and serializer for Java.

> **Fork notice:** This repository ([jhlade/ADSDDL](https://github.com/jhlade/ADSDDL)) is an extended and performance-optimized fork of the original [Tirasa/ADSDDL](https://github.com/Tirasa/ADSDDL) project created by [Tirasa](https://www.tirasa.net/). Package names and Maven coordinates will transition in upcoming releases.

### Key Improvements over Upstream
* Fixed `NumberFacility.getBytes(value, length)` big-endian padding and `SDDLHelper` SID construction (`S-1-1-0` / `S-1-5-10`).
* Direct `ByteBuffer` parsing and zero-copy serialization without `IntBuffer` alignment restrictions.
* Canonical Windows DACL ordering (`ACL.sortCanonical()`, `ACL.addAceCanonical(ACE)`) and wire-format validation for Microsoft Active Directory (2008–2025) and Samba 4.
* Zero-allocation `SID.parse(String)` scanner and `GUID.equals(byte[], String)` comparator.
* Full mutability of `SDDL`, `ACL`, `ACE`, and `SID`, including 16-bit `SddlControlFlag` management and all standard DS `AceRights.ObjectRight` flags.
* Pluggable `AdsddlLogger` facade with optional SLF4J binding, `java.util.logging` support, and silent no-op (`null`) mode.

### Maven Dependency

```xml
<dependency>
  <groupId>net.tirasa</groupId>
  <artifactId>adsddl</artifactId>
  <version>1.10-SNAPSHOT</version>
</dependency>
```

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

> **Fork notice:** This repository ([jhlade/ADSDDL](https://github.com/jhlade/ADSDDL)) is an extended and performance-optimized fork of the original [Tirasa/ADSDDL](https://github.com/Tirasa/ADSDDL) project created by [Tirasa](https://www.tirasa.net/) (originally published under `net.tirasa:adsddl:1.9`).

### Key Improvements over Upstream
* Fixed `NumberFacility.getBytes(value, length)` big-endian padding and `SDDLHelper` SID construction (`S-1-1-0` / `S-1-5-10`).
* Direct `ByteBuffer` parsing and zero-copy serialization without `IntBuffer` alignment restrictions.
* Canonical Windows DACL ordering (`ACL.sortCanonical()`, `ACL.addAceCanonical(ACE)`) and wire-format validation for Microsoft Active Directory (2008–2025) and Samba 4.
* Bidirectional SDDL string parser and formatter (`SDDL.parse(String)`, `SDDL.toSddlString()`, `ACE.parse(String)`) supporting all 38 two-letter `WellKnownSid` aliases with automatic domain SID inference.
* Catalog enums (`AdExtendedRight`, `AdSchemaGuid`, `WellKnownSid`), fluent `AceBuilder`, composable `AceSelector` predicates, and high-level `DaclOperations` recipes (accidental deletion protection, group manager membership, Send-As, OU password reset delegation).
* Pure BER codec (`BerCodec`) and response decoders (`DirSyncResponse`, `PagedResultsResponse`, `ExtendedDNControl`, `PermissiveModifyControl`) without internal JDK `com.sun.jndi.ldap` dependencies.
* Pluggable `AdsddlLogger` facade with optional SLF4J binding, `java.util.logging` support, and silent no-op (`null`) mode.

### Maven Dependency

```xml
<dependency>
  <groupId>cz.jhlade</groupId>
  <artifactId>adsddl</artifactId>
  <version>26.11.0</version>
</dependency>
```

*(Original upstream release by Tirasa: `net.tirasa:adsddl:1.9`)*

### Building and Releasing

```bash
mvn clean verify                                     # build and run unit tests
mvn clean install                                    # install into local ~/.m2 repository
mvn clean deploy -Pcentral-portal-release -s settings.xml  # publish release to Maven Central
```

Versioning follows the `YY.M.P` calendar scheme (e.g. `26.11.0`).

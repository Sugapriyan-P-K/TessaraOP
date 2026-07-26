# Cybersecurity Policy Rules & Conditions Master List

This document contains an exhaustive list of all technical telemetry points, header fields, protocol behaviors, and match criteria used to write security policies across the Network Layer (Layers 3 & 4) and the Application Layer (Layer 7).

---

## 1. Network Layer Rules (Layers 3 & 4)

Network layer rules inspect packet headers, routing parameters, transport mechanics, and connection state states.

### A. Layer 3 (Network / IP Header) Attributes
* **Source IP Address / CIDR Block:** Exact IP address or range originating the network packet.
* **Destination IP Address / CIDR Block:** Exact IP address or range receiving the network packet.
* **IP Version:** Matches strictly on IPv4 or IPv6 traffic.
* **IP Protocol Number:** Identifies the next-level protocol inside the IP payload (e.g., 1 for ICMP, 2 for IGMP, 6 for TCP, 17 for UDP, 47 for GRE, 50 for ESP).
* **Time-to-Live (TTL) / Hop Limit:** Filters packets based on minimum, maximum, or exact TTL values (used to stop OS fingerprinting or network mapping).
* **IP Options Flags:** Inspects or drops packets containing optional configurations like loose source routing, strict source routing, or record route.
* **Fragmentation Flags:** Matches on "Don't Fragment" (DF), "More Fragments" (MF), or specific Fragment Offsets to prevent packet fragmentation evasion or tear-drop attacks.
* **Differentiated Services Code Point (DSCP) / Type of Service (ToS):** Filters packets based on their Quality of Service (QoS) bits.

### B. Layer 4 (Transport Header) Attributes
* **Source Port:** The network port number originating the session (typically ephemeral).
* **Destination Port:** The target port number providing the service (e.g., 80, 443, 22, 3389).
* **TCP Flags:** Inspects exact combinations or states of control flags: `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `ECE`, `CWR` (used to drop invalid scans like Xmas, NULL, or SYN-FIN).
* **TCP Sequence Number:** Validates that sequence numbers match the expected flow window to block blind packet injection attacks.
* **TCP Window Size:** Filters or flags traffic displaying unusual TCP buffer window sizes.
* **ICMP Type and Code:** Restricts specific control messages (e.g., allowing Type 8 Echo Request while blocking Type 3 Destination Unreachable).

### C. Connection State & Volumetric Conditions
* **Connection State:** Matches packets against the firewall state table: `NEW`, `ESTABLISHED`, `RELATED`, or `INVALID`.
* **Connection Rate:** Restricts the maximum number of new connections allowed per second per source IP.
* **Concurrent Connection Limit:** Limits the total number of open, simultaneous connections allowed from a single IP.
* **Packet Rate (PPS):** Limits total packets per second allowed over an interface or per source IP to prevent DDoS.
* **Byte Rate / Bandwidth (BPS):** Restricts the raw data volume throughput allowed per connection or IP.
* **TCP Session Timeout:** Drops connections that remain idle past a configured time limit.

### D. Infrastructure & Threat Intelligence Conditions
* **Geographic Location (Geo-IP):** Maps IP addresses to physical countries, continents, or specific cities.
* **IP Reputation Score:** Cross-references incoming traffic with feeds tracking known malicious IPs, botnet nodes, or spam sources.
* **Proxy / Anonymizer Status:** Matches if the IP belongs to a known Tor exit node, commercial VPN, or public proxy.
* **Autonomous System Number (ASN):** Blocks or allows entire cloud networks, hosting companies, or ISPs (e.g., blocking traffic from all AWS or Azure data center IP blocks).
* **Inbound/Outbound Interface:** Matches traffic based on the specific physical or virtual network interface card (NIC) it enters or leaves (e.g., `eth0`, `wan1`, `vlan10`).

---

## 2. Application Layer Rules (Layer 7)

Application layer rules inspect the actual application behaviors, application protocols, data structures, and decoded payloads.

### A. HTTP/HTTPS Protocol Structural Components
* **HTTP Method (Verb):** Restricts actions by method types: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`, `CONNECT`.
* **Request URI / Path:** Matches exact, relative, or partial URL paths (e.g., `/api/v1/login`, `/admin/config.php`).
* **Query String Parameters:** Inspects key-value pairs following the `?` in a URL (e.g., checking the value of `?id=`).
* **Request Headers (Keys & Values):** Inspects custom and standard header strings (e.g., `Host`, `Authorization`, `Referer`, `Cookie`, `X-Forwarded-For`).
* **User-Agent String:** Identifies browser characteristics or specific script tools (e.g., blocking automated scanners like `sqlmap` or `nikto`).
* **Content-Type:** Enforces allowed formats for incoming payloads (e.g., forcing `application/json` and rejecting `application/x-www-form-urlencoded`).
* **Content-Length:** Sets maximum or minimum size limits on request bodies to prevent buffer overflow attempts.
* **HTTP Status Codes (Response Rules):** Triggers security actions based on downstream server responses (e.g., rate-limiting an IP if it causes too many `401 Unauthorized` or `404 Not Found` responses).
* **HTTP Version:** Rejects outdated or unsupported protocol variations (e.g., HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3).
* **Multipart Form Data Boundaries:** Inspects structural divisions within form-based file uploads.

### B. Payload Content & Signature Conditions
* **Regex / Pattern Matching:** Scans text strings in the URI, body, or headers against signatures for known attack vectors (SQL Injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI), Remote Code Execution (RCE)).
* **File Extension Filtering:** Blocks uploads or downloads of dangerous or executable file extensions (e.g., `.exe`, `.bat`, `.php`, `.sh`, `.jsp`).
* **File Magic Numbers / MIME Validation:** Inspects the actual binary bytes of a file header to ensure the true file type matches its named extension.
* **JSON/XML Schema Validation:** Validates API body structures against strict pre-defined operational schemas to reject unexpected or deformed fields.
* **Data Loss Prevention (DLP) Patterns:** Scans outbound application responses for regular expressions matching confidential info (e.g., Credit Card Numbers, Social Security Numbers, internal API keys).

### C. Cryptographic & TLS Conditions
* **TLS/SSL Version:** Rejects connections using weak or broken protocols (e.g., enforcing TLS 1.2 or TLS 1.3 minimums; blocking SSLv3, TLS 1.0, and TLS 1.1).
* **Cipher Suite Match:** Allows or denies connections based on the cryptographic algorithms negotiated (e.g., blocking weak ciphers like RC4, 3DES, or null ciphers).
* **Server Name Indication (SNI):** Inspects the unencrypted hostname requested during the early TLS handshake phase before encryption is established.
* **Certificate Authority (CA) / Certificate Metadata:** Evaluates client certificates based on issuer validation, expiration dates, revocation lists (CRL/OCSP), or specific Common Names (CN).

### D. Identity, Session, and Advanced Logic Conditions
* **Authentication Token / JWT Validation:** Verifies the cryptographic signature, expiration claims (`exp`), issuer (`iss`), and scope claims within a JSON Web Token.
* **Session Cookie Validity:** Evaluates whether a browser request includes a valid, active session token that matches backend databases.
* **User Role / Group Membership:** Restricts specific URL paths or data fields based on user access control levels (e.g., `Role == 'Administrator'`).
* **API Key Presence:** Verifies that a valid API key string is present in query parameters or headers.
* **Bot / JavaScript Challenge Status:** Validates whether the connecting browser client has successfully passed a background CAPTCHA or silent cryptographic browser challenge.
* **GraphQL Operation Complexity:** Measures and blocks incoming GraphQL queries if they exceed a certain nesting depth or calculation cost threshold to prevent denial of service.
* **WebSocket Protocol Upgrades:** Controls or blocks attempts to upgrade a standard HTTP connection into a persistent WebSocket stream.

---

## 3. Logical Operators (Rule Execution Engines)

All conditions listed above can be modified or tied together using standard logical rule expressions:
* **String Operators:** `Equals`, `Contains`, `Starts With`, `Ends With`, `Matches Regex`.
* **Numeric Operators:** `Less Than`, `Greater Than`, `Equals`, `Greater Than or Equal To`.
* **Set Operators:** `In List`, `Not In List`.
* **Boolean Operators:** `AND`, `OR`, `NOT`.

These are all the fields(as Condition) i want in rules.
Al policy can contain many rules, a rule can contain many conditions.
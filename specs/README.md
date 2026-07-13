# SMB Wire-Protocol Specification Corpus

Curated subset of the Microsoft Open Specifications, scoped to building a Go
library that **exports a filesystem over SMB with pluggable (e.g. custom LDAP)
authentication**. Each spec lives at `<SPECID>/<SPECID>.md` (+ `media/`
diagrams). Search with `grep -rn specs/`.

Provenance and version: see [SOURCES.md](./SOURCES.md).

## Tier 1 — Core (must implement)

| Spec | Role in the library |
|---|---|
| [MS-SMB2](./MS-SMB2/MS-SMB2.md) | **The protocol.** Packet formats + state machines for connection → session → tree → open. NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, WRITE, CLOSE, QUERY_DIRECTORY, QUERY_INFO, SET_INFO, IOCTL, LOCK, OPLOCK_BREAK, CHANGE_NOTIFY, ECHO, CANCEL, LOGOFF, FLUSH. Signing & encryption (HMAC-SHA256 / AES-CMAC / AES-GMAC / AES-CCM/GCM). |
| [MS-DTYP](./MS-DTYP/MS-DTYP.md) | Wire primitives referenced everywhere: `SID`, `SECURITY_DESCRIPTOR`, `ACL`, `FILETIME`, `GUID`, `FILE_NOTIFY_INFORMATION`. |
| [MS-ERREF](./MS-ERREF/MS-ERREF.md) | Every `STATUS_*` error code returned in responses. |

## Tier 1 — Filesystem semantics (VFS behavior + metadata schema)

| Spec | Role in the library |
|---|---|
| [MS-FSCC](./MS-FSCC/MS-FSCC.md) | Info classes & FS control codes carried by QUERY_INFO / SET_INFO / IOCTL (`FileBasicInformation`, `FileStandardInformation`, `FileFsVolumeInformation`, reparse points, etc.). This is the metadata contract for your VFS. |
| [MS-FSA](./MS-FSA/MS-FSA.md) | **Normative FS algorithms** for create/open, read, write, locking, change-notify, oplocks. Defines what a correct VFS *does*, not just the wire format. |

## Tier 1 — Authentication (the pluggable boundary)

> The auth integration point is **MS-SPNG**: SMB2 SESSION_SETUP carries a GSS/SPNEGO
> token; the library hands the token to an `Authenticator` interface you implement
> (e.g. one that validates NTLMSSP or Kerberos against a custom LDAP schema).

| Spec | Role in the library |
|---|---|
| [MS-SPNG](./MS-SPNG/MS-SPNG.md) | SPNEGO — the GSS wrapper that carries auth tokens in SESSION_SETUP. Defines the mechanism-negotiation layer your `Authenticator` plugs into. |
| [MS-NLMP](./MS-NLMP/MS-NLMP.md) | NTLMSSP — default/fallback auth. Implement the challenge/response and validate against your custom credential store. |
| [MS-APDS](./MS-APDS/MS-APDS.md) | Auth-protocol domain support — how an accepted security context becomes a session principal. Defines the boundary between transport auth and the session identity your VFS authorizes against. |

## Tier 2 — Windows client compatibility

| Spec | Role in the library |
|---|---|
| [MS-SRVS](./MS-SRVS/MS-SRVS.md) | Server Service (SRVSVC) over DCE/RPC — `NetShareEnum` / share browsing. Windows Explorer won't list shares without some of this. |
| [MS-RPCE](./MS-RPCE/MS-RPCE.md) | DCE/RPC over SMB **and NDR** (NDR has no standalone spec; the full Network Data Representation rules live here). Transport layer for SRVSVC and named pipes. |
| [MS-SMB](./MS-SMB/MS-SMB.md) | SMB1 — reference only, for multi-protocol negotiation fallback semantics. Do **not** implement. |
| [MS-CIFS](./MS-CIFS/MS-CIFS.md) | Legacy CIFS. Reference/historical context only. |

## Tier 2 — File-server feature family (implement on demand)

| Spec | Feature |
|---|---|
| [MS-DFSC](./MS-DFSC/MS-DFSC.md) | DFS referrals — only if you advertise `SMB2_GLOBAL_CAP_DFS`. |
| [MS-FSRVP](./MS-FSRVP/MS-FSRVP.md) | VSS / shadow-copy requests over SMB. |
| [MS-RSVD](./MS-RSVD/MS-RSVD.md) | Remote Shared Virtual Disk (Hyper-V pass-through). |
| [MS-SQOS](./MS-SQOS/MS-SQOS.md) | Storage QoS policy. |
| [MS-SWN](./MS-SWN/MS-SWN.md) | SMB Witness — async notifications for cluster failover. |

## Tier 3 — Kerberos / Active Directory (optional domain path)

| Spec | Role |
|---|---|
| [MS-KILE](./MS-KILE/MS-KILE.md) | Microsoft Kerberos protocol extensions. Needed only for domain/AD auth. |
| [MS-PAC](./MS-PAC/MS-PAC.md) | Privilege Attribute Certificate — auth data carried inside Kerberos tickets (groups/SIDs). |
| [MS-ADTS](./MS-ADTS/MS-ADTS.md) | Active Directory technical spec / schema. Reference if mapping a custom LDAP schema to AD-style identity. |
| [MS-LSAD](./MS-LSAD/MS-LSAD.md) | LSA policy remote protocol (domain/SID policy). |
| [MS-LSAT](./MS-LSAT/MS-LSAT.md) | LSA translation — name↔SID resolution. |
| [MS-SAMR](./MS-SAMR/MS-SAMR.md) | SAM remote protocol — account/group management RPC. |
| [MS-DRSR](./MS-DRSR/MS-DRSR.md) | Directory replication service (AD replication). Rarely needed for a server. |
| [MS-AZOD](./MS-AZOD/MS-AZOD.md) | Authorization protocol (niche). |
| [MS-ADOD](./MS-ADOD/MS-ADOD.md) | Authentication over DHCP/OD (niche). |

## Transport (advanced)

| Spec | Role |
|---|---|
| [MS-SMBD](./MS-SMBD/MS-SMBD.md) | SMB Direct — RDMA transport (SMB3). Optional; QUIC/Direct-TCP/NetBIOS are covered in MS-SMB2 §2.1. |

## Suggested implementation order

1. **Transport + framing** — Direct-TCP / NetBIOS framing (MS-SMB2 §2.1).
2. **Packet codec** — SMB2 header + NEGOTIATE (MS-SMB2).
3. **Auth interface** — SPNEGO demux (MS-SPNG) → NTLMSSP (MS-NLMP) backed by your LDAP store; map to session principal (MS-APDS, MS-DTYP).
4. **VFS interface** — model semantics on MS-FSA, expose metadata via MS-FSCC info classes.
5. **Command handlers** — TREE_CONNECT, CREATE/READ/WRITE/CLOSE, QUERY_DIRECTORY, QUERY_INFO/SET_INFO (MS-SMB2).
6. **Windows compat** — SRVSVC share enumeration over MS-RPCE (MS-SRVS).
7. **Hardening** — signing/encryption (MS-SMB2 §3.x), then Tier 2/3 features as needed.

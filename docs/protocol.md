# Protocol Support

## Dialects

| Dialect | Constant | Status |
|---------|----------|--------|
| SMB 2.0.2 | `DialectSMB202` | ✅ Signing via HMAC-SHA256 |
| SMB 2.1 | `DialectSMB21` | ✅ |
| SMB 3.0 | `DialectSMB30` | ✅ AES-CMAC signing, AES-CCM encryption |
| SMB 3.0.2 | `DialectSMB302` | ✅ Default |
| SMB 3.1.1 | `DialectSMB311` | ✅ Preauth integrity (SHA-512) |

## Commands

| Code | Command | Status |
|------|---------|--------|
| 0x00 | NEGOTIATE | ✅ |
| 0x01 | SESSION_SETUP | ✅ SPNEGO + NTLMv2 |
| 0x02 | LOGOFF | ✅ |
| 0x03 | TREE_CONNECT | ✅ |
| 0x04 | TREE_DISCONNECT | ✅ |
| 0x05 | CREATE | ✅ All dispositions, oplocks, delete-on-close |
| 0x06 | CLOSE | ✅ |
| 0x07 | FLUSH | ✅ |
| 0x08 | READ | ✅ Zero-allocation (direct buffer write) |
| 0x09 | WRITE | ✅ |
| 0x0A | LOCK | ✅ Byte-range (shared/exclusive/unlock) |
| 0x0B | IOCTL | ✅ See FSCTL table |
| 0x0C | CANCEL | ✅ Async cancellation by AsyncId |
| 0x0D | ECHO | ✅ |
| 0x0E | QUERY_DIRECTORY | ✅ FileDirectoryInformation, FileIdBothDirectoryInformation |
| 0x0F | CHANGE_NOTIFY | ✅ Async polling-based |
| 0x10 | QUERY_INFO | ✅ File + filesystem info classes |
| 0x11 | SET_INFO | ✅ FileDisposition, FileBasic, FileEndOfFile, FileRename |
| 0x12 | OPLOCK_BREAK | ✅ Level 1 exclusive + acknowledgment |

## FSCTL Codes

| Code | Name | Status |
|------|------|--------|
| 0x00140204 | FSCTL_VALIDATE_NEGOTIATE_INFO | ✅ Anti-downgrade |
| 0x001401FC | FSCTL_QUERY_NETWORK_INTERFACE_INFO | ✅ Empty response |
| 0x00110018 | FSCTL_PIPE_WAIT | ✅ Named pipe wait |
| 0x0011C017 | FSCTL_PIPE_TRANSCEIVE | ✅ Named pipe RPC |
| 0x001440F2 | FSCTL_SRV_COPYCHUNK | ✅ Via `vfs.Copier` |

## QUERY/SET_INFO Classes

| Class | Name | Q | S |
|-------|------|---|---|
| 0x04 | FileBasicInformation | ✅ | ✅ |
| 0x05 | FileStandardInformation | ✅ | — |
| 0x0A | FileRenameInformation | — | ✅ |
| 0x0D | FileDispositionInformation | — | ✅ |
| 0x12 | FileAllInformation | ✅ | — |
| 0x14 | FileEndOfFileInformation | — | ✅ |
| 0x22 | FileNetworkOpenInformation | ✅ | — |
| 0x01 | FileFsAttributeInformation | ✅ | — |
| 0x03 | FileFsSizeInformation | ✅ | — |
| 0x01 | FileFsVolumeInformation | ✅ | — |

## Oplocks

| Type | Status |
|------|--------|
| Level 1 Exclusive (0x08) | ✅ Grant + async break |
| Batch (0x09) | ✅ |
| Level II (0x01) | ✅ |
| Lease | ❌ |

Oplocks released on CLOSE. Conflicting CREATE triggers async OPLOCK_BREAK
notification via the connection's `asyncResp` channel.

## Preauth Integrity (SMB 3.1.1)

SHA-512 hash chain updated on every NEGOTIATE and SESSION_SETUP exchange
(both request and response). `SMB2_PREAUTH_INTEGRITY_CAPABILITIES` negotiate
context advertised for dialect 3.1.1.

## Capabilities

| Capability | Status |
|------------|--------|
| Large MTU | ✅ |
| Encryption | ✅ (when `WithEncryptionRequired`) |
| DFS | ❌ |
| Leasing | ❌ |
| Multi Channel | ❌ |
| Persistent Handles | ❌ |

## Transport

Direct-TCP (port 445) with 4-byte length-prefixed framing. `FramedConn` reuses
its read buffer and header buffer across messages — zero per-read allocation.

## Leak guarantees

- Per-connection child context cancelled on disconnect
- `cleanup()` closes all file handles, cancels all pending ops
- `sendFinal` / `sendOplockBreak` use non-blocking channel sends
- `pipeHandle.Close` unblocks waiting `Read` calls
- Verified by `TestNoLeakOnDisconnect`, `TestNoLeakOnGracefulShutdown`

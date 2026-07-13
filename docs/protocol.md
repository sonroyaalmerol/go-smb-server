# Protocol Support

This document catalogs the SMB2/3 protocol features implemented by go-smb-server, with references to the relevant Microsoft Open Specifications.

## Dialects

| Dialect | Constant | Status |
|---------|----------|--------|
| SMB 2.0.2 | `wire.DialectSMB202` | ✅ Negotiated, signing via HMAC-SHA256 |
| SMB 2.1 | `wire.DialectSMB21` | ✅ Negotiated |
| SMB 3.0 | `wire.DialectSMB30` | ✅ Negotiated, AES-128-CMAC signing, AES-128-CCM encryption |
| SMB 3.0.2 | `wire.DialectSMB302` | ✅ Default |
| SMB 3.1.1 | `wire.DialectSMB311` | ⚠️ Negotiated but preauth integrity not implemented |

## Commands

| Code | Command | MS-SMB2 § | Status |
|------|---------|-----------|--------|
| 0x00 | NEGOTIATE | 2.2.3 | ✅ Dialect selection, capabilities, negotiate contexts |
| 0x01 | SESSION_SETUP | 2.2.5 | ✅ SPNEGO + NTLMv2, signing/encryption key setup |
| 0x02 | LOGOFF | 2.2.7 | ✅ |
| 0x03 | TREE_CONNECT | 2.2.9 | ✅ Share name resolution |
| 0x04 | TREE_DISCONNECT | 2.2.11 | ✅ |
| 0x05 | CREATE | 2.2.13 | ✅ All dispositions, directory create, delete-on-close |
| 0x06 | CLOSE | 2.2.15 | ✅ Delete-on-close via Remover |
| 0x07 | FLUSH | 2.2.17 | ✅ No-op |
| 0x08 | READ | 2.2.19 | ✅ Positioned read, STATUS_END_OF_FILE at EOF |
| 0x09 | WRITE | 2.2.21 | ✅ Positioned write |
| 0x0A | LOCK | 2.2.26 | ✅ Per-file byte-range locks (shared/exclusive/unlock) |
| 0x0B | IOCTL | 2.2.31 | ✅ FSCTL_VALIDATE_NEGOTIATE_INFO, FSCTL_QUERY_NETWORK_INTERFACE_INFO |
| 0x0C | CANCEL | 2.2.30 | ✅ Async operation cancellation by AsyncId |
| 0x0D | ECHO | 2.2.28 | ✅ |
| 0x0E | QUERY_DIRECTORY | 2.2.33 | ✅ FileDirectoryInformation, FileIdBothDirectoryInformation |
| 0x0F | CHANGE_NOTIFY | 2.2.35 | ✅ Async polling-based directory change notification |
| 0x10 | QUERY_INFO | 2.2.37 | ✅ File info classes, filesystem info classes (see below) |
| 0x11 | SET_INFO | 2.2.39 | ✅ FileDispositionInformation, FileBasicInformation, FileEndOfFileInformation |
| 0x12 | OPLOCK_BREAK | — | ❌ Not implemented |
| 0x13 | SERVER_NOTIFY | — | ❌ Not implemented |

## QUERY_INFO File Information Classes

| Class | Name | MS-FSCC § | Status |
|-------|------|-----------|--------|
| 0x04 | FileBasicInformation | 2.4.7 | ✅ |
| 0x05 | FileStandardInformation | 2.4.14 | ✅ |
| 0x12 | FileAllInformation | 2.4.2 | ✅ |
| 0x22 | FileNetworkOpenInformation | 2.4.27 | ✅ |

## QUERY_INFO File System Information Classes

| Class | Name | MS-FSCC § | Status |
|-------|------|-----------|--------|
| 0x05 | FileFsAttributeInformation | 2.5.1 | ✅ |
| 0x03 | FileFsSizeInformation | 2.5.8 | ✅ Partial |
| 0x01 | FileFsVolumeInformation | 2.5.9 | ✅ |

## QUERY_DIRECTORY Information Classes

| Class | Name | MS-FSCC § | Status |
|-------|------|-----------|--------|
| 0x01 | FileDirectoryInformation | 2.4.10 | ✅ |
| 0x25 | FileIdBothDirectoryInformation | 2.4.22 | ✅ |

## FSCTL Codes (IOCTL)

| Code | Name | Status |
|------|------|--------|
| 0x00140204 | FSCTL_VALIDATE_NEGOTIATE_INFO | ✅ Anti-downgrade validation |
| 0x001401FC | FSCTL_QUERY_NETWORK_INTERFACE_INFO | ✅ Empty response (no RDMA) |
| 0x00060194 | FSCTL_DFS_GET_REFERRALS | ❌ |
| 0x001440F2 | FSCTL_SRV_COPYCHUNK | ❌ |

## Named Pipes & DCE/RPC

| Feature | Status |
|---------|--------|
| IPC$ share auto-registration | ✅ |
| SRVSVC pipe (\srvsvc) | ✅ NetrShareEnum (opnum 15) returning SHARE_INFO_1 |
| DCE/RPC BIND/BIND_ACK | ✅ Connection-oriented PDU |
| DCE/RPC REQUEST/RESPONSE | ✅ Minimal codec |
| FSCTL_PIPE_WAIT / FSCTL_PIPE_TRANSCEIVE | ❌ |
| Windows Explorer share browsing | ⚠️ Infrastructure in place; smbclient -L needs IOCTL debugging |

## NTSTATUS Codes

28 status codes defined in `smb/wire/status.go` covering all standard SMB2 responses:

```
STATUS_SUCCESS, STATUS_PENDING, STATUS_CANCELLED, STATUS_NOT_IMPLEMENTED,
STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_FILE,
STATUS_INVALID_DEVICE_REQUEST, STATUS_END_OF_FILE, STATUS_MORE_PROCESSING_REQUIRED,
STATUS_NO_MEMORY, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL,
STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_NAME_COLLISION,
STATUS_OBJECT_PATH_NOT_FOUND, STATUS_LOCK_CONFLICT, STATUS_INSUFFICIENT_RESOURCES,
STATUS_NOT_SUPPORTED, STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY,
STATUS_LOGON_FAILURE, STATUS_BAD_NETWORK_NAME, STATUS_NETWORK_NAME_DELETED,
STATUS_NO_MORE_FILES, STATUS_USER_SESSION_DELETED, STATUS_INFO_LENGTH_MISMATCH,
STATUS_INVALID_NETWORK_RESPONSE
```

## Capabilities

| Capability | Flag | Status |
|------------|------|--------|
| DFS | 0x00000001 | ❌ |
| Leasing | 0x00000002 | ❌ |
| Large MTU | 0x00000004 | ✅ Always advertised |
| Multi Channel | 0x00000008 | ❌ |
| Persistent Handles | 0x00000010 | ❌ |
| Directory Leasing | 0x00000020 | ❌ |
| Encryption | 0x00000040 | ✅ Advertised when `WithEncryptionRequired()` |

## Transport

- Direct-TCP transport (port 445) with 4-byte length-prefixed framing (MS-SMB2 §2.1).
- NetBIOS framing is not implemented.
- Reusable read buffers per connection.
- `sync.Pool` for connection buffers.

## Async framework

The server supports asynchronous operations:

- SMB2 CANCEL resolves pending operations by `AsyncId`.
- CHANGE_NOTIFY spawns a watcher goroutine that polls the directory for changes.
- Interim `STATUS_PENDING` responses with `FlagAsyncCommand` are sent to keep the connection alive.
- The read loop uses a 200ms deadline to periodically drain async final responses from an `asyncResp` channel.

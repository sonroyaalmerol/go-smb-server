package wire

import "fmt"

const (
	StatusSuccess                uint32 = 0x00000000
	StatusInvalidHandle          uint32 = 0xC0000008
	StatusNotImplemented         uint32 = 0xC0000002
	StatusInvalidParameter       uint32 = 0xC000000D
	StatusNoSuchFile             uint32 = 0xC000000F
	StatusInvalidDeviceRequest   uint32 = 0xC0000010
	StatusEndOfFile              uint32 = 0xC0000011
	StatusMoreProcessingRequired uint32 = 0xC0000016
	StatusNoMemory               uint32 = 0xC0000017
	StatusAccessDenied           uint32 = 0xC0000022
	StatusBufferTooSmall         uint32 = 0xC0000023
	StatusObjectNameNotFound     uint32 = 0xC0000034
	StatusObjectNameCollision    uint32 = 0xC0000035
	StatusObjectPathNotFound     uint32 = 0xC000003A
	StatusInsufficientResources  uint32 = 0xC000009A
	StatusFileIsADirectory       uint32 = 0xC00000BA
	StatusNotSupported           uint32 = 0xC00000BB
	StatusNotADirectory          uint32 = 0xC0000103
	StatusLogonFailure           uint32 = 0xC000006D
	StatusBadNetworkName         uint32 = 0xC00000CC
	StatusNetworkNameDeleted     uint32 = 0xC00000C9
	StatusNoMoreFiles            uint32 = 0x80000006
	StatusUserSessionDeleted     uint32 = 0xC0000203
)

type NTError struct {
	Status uint32
}

func (e *NTError) Error() string {
	return fmt.Sprintf("ntstatus 0x%08X", e.Status)
}

func NewNTError(status uint32) *NTError { return &NTError{Status: status} }

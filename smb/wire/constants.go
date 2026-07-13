package wire

var SMB2ProtocolId = [4]byte{0xFE, 'S', 'M', 'B'}

const HeaderSize = 64

const (
	CmdNegotiate      uint16 = 0x0000
	CmdSessionSetup   uint16 = 0x0001
	CmdLogoff         uint16 = 0x0002
	CmdTreeConnect    uint16 = 0x0003
	CmdTreeDisconnect uint16 = 0x0004
	CmdCreate         uint16 = 0x0005
	CmdClose          uint16 = 0x0006
	CmdFlush          uint16 = 0x0007
	CmdRead           uint16 = 0x0008
	CmdWrite          uint16 = 0x0009
	CmdLock           uint16 = 0x000A
	CmdIoctl          uint16 = 0x000B
	CmdCancel         uint16 = 0x000C
	CmdEcho           uint16 = 0x000D
	CmdQueryDirectory uint16 = 0x000E
	CmdChangeNotify   uint16 = 0x000F
	CmdQueryInfo      uint16 = 0x0010
	CmdSetInfo        uint16 = 0x0011
	CmdOplockBreak    uint16 = 0x0012
	CmdServerNotify   uint16 = 0x0013
)

const (
	FlagServerToRedir   uint32 = 0x00000001
	FlagAsyncCommand    uint32 = 0x00000002
	FlagRelatedOps      uint32 = 0x00000004
	FlagSigned          uint32 = 0x00000008
	FlagPriorityMask    uint32 = 0x00000070
	FlagDfsOperations   uint32 = 0x10000000
	FlagReplayOperation uint32 = 0x20000000
)

const (
	DialectSMB202   uint16 = 0x0202
	DialectSMB21    uint16 = 0x0210
	DialectSMB30    uint16 = 0x0300
	DialectSMB302   uint16 = 0x0302
	DialectSMB311   uint16 = 0x0311
	DialectWildcard uint16 = 0x02FF
)

const (
	SigningEnabled  uint16 = 0x0001
	SigningRequired uint16 = 0x0002
)

const (
	CapDFS               uint32 = 0x00000001
	CapLeasing           uint32 = 0x00000002
	CapLargeMTU          uint32 = 0x00000004
	CapMultiChannel      uint32 = 0x00000008
	CapPersistentHandles uint32 = 0x00000010
	CapDirectoryLeasing  uint32 = 0x00000020
	CapEncryption        uint32 = 0x00000040
	CapNotifications     uint32 = 0x00000080
)

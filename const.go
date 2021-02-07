package socks5

// VERSION socks version
const VERSION = 5

// Method auth method
type Method byte

const (
	// MethodNoAuth no auth method
	MethodNoAuth = Method(0x00)
	// MethodGSSAPI gss api method
	MethodGSSAPI = Method(0x01)
	// MethodUserPass user pass method
	MethodUserPass = Method(0x02)
	// MethodNotSupport not support method
	MethodNotSupport = Method(0xff)
)

// Cmd cmd
type Cmd byte

const (
	// CmdConnect connect target
	CmdConnect = Cmd(0x01)
	// CmdBind bind local
	CmdBind = Cmd(0x02)
	// CmdUDPForward forward udp data
	CmdUDPForward = Cmd(0x03)
	// CmdUnknown unknown command
	CmdUnknown = Cmd(0xff)
)

func (m Method) String() string {
	switch m {
	case MethodNoAuth:
		return "noauth"
	case MethodGSSAPI:
		return "gssapi"
	case MethodUserPass:
		return "user/pass"
	case MethodNotSupport:
		return "not support"
	}
	return ""
}

// AType addr type
type AType byte

const (
	// AddrIPV4 ipv4 type
	AddrIPV4 = AType(0x01)
	// AddrDomain domain type
	AddrDomain = AType(0x03)
	// AddrIPV6 ipv6 type
	AddrIPV6 = AType(0x04)
	// AddrUnknown unknown type
	AddrUnknown = AType(0xff)
)

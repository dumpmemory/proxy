package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

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

// Addr address
type Addr struct {
	Type   AType
	IP     net.IP
	Port   uint16
	Domain string
}

func (a Addr) String() string {
	switch a.Type {
	case AddrIPV4, AddrIPV6:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case AddrDomain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	default:
		return ""
	}
}

// Bytes compact address
func (a Addr) Bytes() []byte {
	var buf bytes.Buffer
	switch a.Type {
	case AddrIPV4:
		buf.WriteByte(byte(AddrIPV4))
		binary.Write(&buf, binary.BigEndian, a.IP.To4())
	case AddrIPV6:
		buf.WriteByte(byte(AddrIPV6))
		binary.Write(&buf, binary.BigEndian, a.IP.To16())
	case AddrDomain:
		buf.WriteByte(byte(AddrDomain))
		buf.WriteByte(byte(len(a.Domain)))
		buf.WriteString(a.Domain)
	default:
		buf.WriteByte(byte(AddrIPV4))
		binary.Write(&buf, binary.BigEndian, a.IP.To4())
	}
	binary.Write(&buf, binary.BigEndian, a.Port)
	return buf.Bytes()
}

// Reply reply
type Reply byte

const (
	// ReplyOK ok
	ReplyOK = Reply(0x00)
	// ReplyConnectionRefused connection refused
	ReplyConnectionRefused = Reply(0x01)
	// ReplyRuleDisabled rule disable
	ReplyRuleDisabled = Reply(0x02)
	// ReplyNetworkUnavailable net unavailable
	ReplyNetworkUnavailable = Reply(0x03)
	// ReplyHostUnavailable host unavailable
	ReplyHostUnavailable = Reply(0x04)
	// ReplyResetByPeer connection reset by peer
	ReplyResetByPeer = Reply(0x05)
	// ReplyTTLExpired ttl expired
	ReplyTTLExpired = Reply(0x06)
	// ReplyUnsupportCmd unsupport command
	ReplyUnsupportCmd = Reply(0x07)
	// ReplyUnsupportAddr unsupport address
	ReplyUnsupportAddr = Reply(0x08)
)

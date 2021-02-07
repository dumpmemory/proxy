package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
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

package addr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Type addr type
type Type byte

// definded by socks5
const (
	// AddrIPV4 ipv4 type
	IPV4 = Type(0x01)
	// AddrDomain domain type
	Domain = Type(0x03)
	// AddrIPV6 ipv6 type
	IPV6 = Type(0x04)
	// AddrUnknown unknown type
	Unknown = Type(0xff)
)

// Addr address
type Addr struct {
	Type   Type
	IP     net.IP
	Port   uint16
	Domain string
}

func (a Addr) String() string {
	switch a.Type {
	case IPV4, IPV6:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case Domain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	default:
		return ""
	}
}

// Bytes compact address
func (a Addr) Bytes() []byte {
	var buf bytes.Buffer
	switch a.Type {
	case IPV4:
		buf.WriteByte(byte(IPV4))
		binary.Write(&buf, binary.BigEndian, a.IP.To4())
	case IPV6:
		buf.WriteByte(byte(IPV6))
		binary.Write(&buf, binary.BigEndian, a.IP.To16())
	case Domain:
		buf.WriteByte(byte(Domain))
		buf.WriteByte(byte(len(a.Domain)))
		buf.WriteString(a.Domain)
	default:
		buf.WriteByte(byte(IPV4))
		binary.Write(&buf, binary.BigEndian, a.IP.To4())
	}
	binary.Write(&buf, binary.BigEndian, a.Port)
	return buf.Bytes()
}

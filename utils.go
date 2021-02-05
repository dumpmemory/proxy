package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func errInfo(c net.Conn, err error) string {
	return fmt.Sprintf("; addr=%s, err=%v", c.RemoteAddr().String(), err)
}

func writeTimeout(c net.Conn, data []byte, timeout time.Duration) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.Write(data)
	return err
}

func waitHandshake(c net.Conn, timeout time.Duration) ([]Method, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	var hdr [2]byte
	_, err := io.ReadFull(c, hdr[:])
	if err != nil {
		return nil, err
	}
	if hdr[0] != VERSION {
		return nil, ErrVersion
	}
	methods := make([]byte, hdr[1])
	_, err = io.ReadFull(c, methods[:])
	if err != nil {
		return nil, err
	}
	ret := make([]Method, hdr[1])
	for i := range methods {
		ret[i] = Method(methods[i])
	}
	return ret, nil
}

func waitUserPass(c net.Conn, timeout time.Duration) (string, string, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	var hdr [2]byte
	_, err := io.ReadFull(c, hdr[:])
	if err != nil {
		return "", "", err
	}
	if hdr[0] != 0x01 {
		return "", "", fmt.Errorf("invalid user/pass header: %d", hdr[0])
	}
	user := make([]byte, hdr[1])
	_, err = io.ReadFull(c, user[:])
	if err != nil {
		return "", "", err
	}
	var l [1]byte
	_, err = c.Read(l[:])
	if err != nil {
		return "", "", err
	}
	pass := make([]byte, l[0])
	_, err = io.ReadFull(c, pass[:])
	if err != nil {
		return "", "", err
	}
	return string(user), string(pass), nil
}

func readIPAddr(c net.Conn, length int) (net.IP, uint16, error) {
	ip := make(net.IP, length)
	err := binary.Read(c, binary.BigEndian, &ip)
	if err != nil {
		return nil, 0, err
	}
	var port uint16
	err = binary.Read(c, binary.BigEndian, &port)
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

func waitRequest(c net.Conn, timeout time.Duration) (Cmd, Addr, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	t := Addr{Type: AddrUnknown}
	var hdr [4]byte
	_, err := io.ReadFull(c, hdr[:])
	if err != nil {
		return CmdUnknown, t, err
	}
	if hdr[0] != VERSION {
		return CmdUnknown, t, ErrVersion
	}
	cmd := Cmd(hdr[1])
	t.Type = AType(hdr[3])
	switch t.Type {
	case AddrIPV4:
		t.IP, t.Port, err = readIPAddr(c, net.IPv4len)
	case AddrIPV6:
		t.IP, t.Port, err = readIPAddr(c, net.IPv6len)
	case AddrDomain:
		var l [1]byte
		_, err = c.Read(l[:])
		if err != nil {
			return cmd, t, err
		}
		data := make([]byte, l[0]+2)
		_, err = io.ReadFull(c, data)
		if err != nil {
			return cmd, t, err
		}
		t.Domain = string(data[:l[0]])
		t.Port = binary.BigEndian.Uint16(data[l[0]:])
		return cmd, t, nil
	}
	return cmd, t, err
}

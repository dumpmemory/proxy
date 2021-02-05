package socks5

import (
	"io"
	"log"
	"net"
)

type defaultServerHandler struct{}

func (h defaultServerHandler) Handshake(methods []Method) Method {
	for _, m := range methods {
		if m == MethodNoAuth {
			return m
		}
	}
	return MethodNotSupport
}

func (h defaultServerHandler) LogDebug(format string, a ...interface{}) {
	log.Printf("[DEBUG]"+format, a...)
}

func (h defaultServerHandler) LogInfo(format string, a ...interface{}) {
	log.Printf("[INFO]"+format, a...)
}

func (h defaultServerHandler) LogError(format string, a ...interface{}) {
	log.Printf("[ERROR]"+format, a...)
}

func (h defaultServerHandler) CheckUserPass(user, pass string) bool {
	return true
}

func (h defaultServerHandler) Connect(addr Addr) (io.ReadWriter, Addr, error) {
	var remote *net.TCPConn
	var err error
	switch addr.Type {
	case AddrIPV4, AddrIPV6:
		remote, err = net.DialTCP("tcp", nil, &net.TCPAddr{IP: addr.IP, Port: int(addr.Port)})
	case AddrDomain:
		a, err := net.ResolveTCPAddr("tcp", addr.String())
		if err != nil {
			return nil, addr, err
		}
		remote, err = net.DialTCP("tcp", nil, a)
	}
	if err != nil {
		return nil, addr, err
	}
	return remote, addr, nil
}

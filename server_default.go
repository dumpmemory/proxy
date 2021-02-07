package socks5

import (
	"context"
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

func (h defaultServerHandler) Connect(addr Addr) (net.Conn, Addr, error) {
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

// netCopy copy from io.Copy
func netCopy(ctx context.Context, cancel context.CancelFunc, dst io.Writer, src io.Reader) (int, error) {
	defer cancel()
	const size = 32 * 1024
	buf := make([]byte, size)
	var written int
	for {
		select {
		case <-ctx.Done():
			return written, nil
		default:
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			// fmt.Printf("%s\n", hex.Dump(buf[:nr]))
			if nw > 0 {
				written += nw
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			return written, nil
		}
	}
}

func (h defaultServerHandler) Forward(local, remote net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go netCopy(ctx, cancel, local, remote)
	netCopy(ctx, cancel, remote, local)
}

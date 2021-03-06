package http

import (
	"context"
	"io"
	"log"
	"net"

	"github.com/lwch/proxy/addr"
)

type defaultServerHandler struct{}

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

func (h defaultServerHandler) Connect(from string, to addr.Addr) (io.ReadWriteCloser, addr.Addr, error) {
	var remote *net.TCPConn
	var err error
	switch to.Type {
	case addr.IPV4, addr.IPV6:
		remote, err = net.DialTCP("tcp", nil, &net.TCPAddr{IP: to.IP, Port: int(to.Port)})
	case addr.Domain:
		var addr *net.TCPAddr
		addr, err = net.ResolveTCPAddr("tcp", to.String())
		if err != nil {
			return nil, to, err
		}
		remote, err = net.DialTCP("tcp", nil, addr)
	}
	if err != nil {
		return nil, to, err
	}
	return remote, to, nil
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

func (h defaultServerHandler) Forward(local, remote io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go netCopy(ctx, cancel, local, remote)
	netCopy(ctx, cancel, remote, local)
}

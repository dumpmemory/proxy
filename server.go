package socks5

import (
	"context"
	"net"
	"strings"
	"time"
)

// ServerHandler server handler
type ServerHandler interface {
	LogDebug(format string, a ...interface{})
	LogError(format string, a ...interface{})
	LogInfo(format string, a ...interface{})
	Handshake(methods []Method) Method
	CheckUserPass(user, pass string) bool
	Connect(a Addr) (net.Conn, Addr, error)
	Forward(local, remote net.Conn)
}

// ServerConf server config
type ServerConf struct {
	ReadTimeout  time.Duration // Default: 1s
	WriteTimeout time.Duration // Default: 1s
	Handler      ServerHandler
}

// SetDefault check and set default value
func (cfg *ServerConf) SetDefault() {
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = time.Second
	}
	if cfg.Handler == nil {
		cfg.Handler = defaultServerHandler{}
	}
}

// Server socks5 server
type Server struct {
	cfg      ServerConf
	listener *net.TCPListener

	// runtime
	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer create server
func NewServer(cfg ServerConf) *Server {
	cfg.SetDefault()
	svr := &Server{cfg: cfg}
	svr.ctx, svr.cancel = context.WithCancel(context.Background())
	return svr
}

// Shutdown service shutdown
func (s *Server) Shutdown() {
	s.cancel()
	s.listener.Close()
}

// ListenAndServe listen and serve
func (s *Server) ListenAndServe(addr string) error {
	resAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	s.listener, err = net.ListenTCP("tcp", resAddr)
	if err != nil {
		return err
	}
	for {
		select {
		case <-s.ctx.Done():
			return nil
		default:
			s.listener.SetDeadline(time.Now().Add(time.Second))
			conn, err := s.listener.Accept()
			if err != nil {
				continue
			}
			go s.handleSocket(conn)
		}
	}
}

var errAddr Addr

func (s *Server) handleSocket(c net.Conn) {
	defer c.Close()
	methods, err := waitHandshake(c, s.cfg.ReadTimeout)
	if err != nil {
		s.cfg.Handler.LogError("waitHandshake failed" + errInfo(c, err))
		return
	}
	m := s.cfg.Handler.Handshake(methods)
	err = writeTimeout(c, []byte{VERSION, byte(m)}, s.cfg.WriteTimeout)
	if err != nil {
		s.cfg.Handler.LogError("reply handshake failed, method=%s"+errInfo(c, err), m)
		return
	}
	if m == MethodUserPass {
		user, pass, err := waitUserPass(c, s.cfg.ReadTimeout)
		if err != nil {
			s.cfg.Handler.LogError("waitUserPass failed" + errInfo(c, err))
			return
		}
		ok := s.cfg.Handler.CheckUserPass(user, pass)
		if ok {
			err = writeTimeout(c, []byte{0x01, 0x00}, s.cfg.WriteTimeout)
		} else {
			err = writeTimeout(c, []byte{0x01, 0x01}, s.cfg.WriteTimeout)
		}
		if err != nil {
			s.cfg.Handler.LogError("reply user/pass failed" + errInfo(c, err))
			return
		}
	}
	cmd, addr, err := waitRequest(c, s.cfg.ReadTimeout)
	if err != nil {
		s.cfg.Handler.LogError("waitRequest failed" + errInfo(c, err))
		return
	}
	var remote net.Conn
	switch cmd {
	case CmdConnect:
		var nextAddr Addr
		remote, nextAddr, err = s.cfg.Handler.Connect(addr)
		if err != nil {
			msg := err.Error()
			t := ReplyUnsupportCmd
			switch {
			case strings.Contains(msg, "refused"):
				t = ReplyConnectionRefused
			case strings.Contains(msg, "network is unreachable"):
				t = ReplyNetworkUnavailable
			}
			err = writeTimeout(c, append([]byte{VERSION, byte(t), 0x00},
				errAddr.Bytes()...), s.cfg.WriteTimeout)
			return
		}
		defer remote.Close()
		err = writeTimeout(c, append([]byte{VERSION, byte(ReplyOK), 0x00},
			nextAddr.Bytes()...), s.cfg.WriteTimeout)
	case CmdBind:
		err = writeTimeout(c, append([]byte{VERSION, byte(ReplyUnsupportCmd), 0x00},
			errAddr.Bytes()...), s.cfg.WriteTimeout)
	case CmdUDPForward:
		err = writeTimeout(c, append([]byte{VERSION, byte(ReplyUnsupportCmd), 0x00},
			errAddr.Bytes()...), s.cfg.WriteTimeout)
	}
	if err != nil {
		s.cfg.Handler.LogError("handle failed" + errInfo(c, err))
		return
	}
	s.cfg.Handler.Forward(c, remote)
}

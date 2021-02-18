package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/lwch/proxy/addr"
)

// ServerHandler server handler
type ServerHandler interface {
	LogDebug(format string, a ...interface{})
	LogError(format string, a ...interface{})
	LogInfo(format string, a ...interface{})
	CheckUserPass(user, pass string) bool
	Connect(a addr.Addr) (io.ReadWriteCloser, addr.Addr, error)
	Forward(local, remote io.ReadWriteCloser)
}

// ServerConf server config
type ServerConf struct {
	ReadTimeout  time.Duration // Default: 1s
	WriteTimeout time.Duration // Default: 1s
	Key          string
	Crt          string
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
	cfg ServerConf
	svr *http.Server
}

// NewServer create server
func NewServer(cfg ServerConf, addr string) *Server {
	cfg.SetDefault()
	svr := &Server{
		cfg: cfg,
		svr: &http.Server{
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			Addr:         addr,
		},
	}
	svr.svr.Handler = svr
	return svr
}

// Shutdown service shutdown
func (s *Server) Shutdown() {
	s.svr.Shutdown(context.Background())
}

// ListenAndServe listen and serve
func (s *Server) ListenAndServe() error {
	return s.svr.ListenAndServe()
}

// ListenAndServeTLS listen and serve tls
func (s *Server) ListenAndServeTLS() error {
	return s.svr.ListenAndServeTLS(s.cfg.Crt, s.cfg.Key)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// fix DumpRequest missing Host header
	req.RequestURI = ""
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	var a addr.Addr
	if ip := net.ParseIP(host); ip == nil {
		a.Type = addr.Domain
		a.Domain = host
	} else if len(ip) == net.IPv4len {
		a.Type = addr.IPV4
		a.IP = ip
	} else {
		a.Type = addr.IPV6
		a.IP = ip
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err == nil {
		a.Port = uint16(n)
	}
	if a.Port == 0 {
		if req.Method == http.MethodConnect {
			a.Port = 443
		} else {
			a.Port = 80
		}
	}
	remote, _, err := s.cfg.Handler.Connect(a)
	if err != nil {
		s.cfg.Handler.LogError("connect %s failed"+errInfo(req.RemoteAddr, err), a.String())
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.cfg.Handler.LogError("not supported hijacker, addr=%s", req.RemoteAddr)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		s.cfg.Handler.LogError("hijack failed" + errInfo(req.RemoteAddr, err))
		return
	}
	if req.Method == http.MethodConnect {
		err = replyOK(conn)
		if err != nil {
			s.cfg.Handler.LogError("replyOK failed" + errInfo(req.RemoteAddr, err))
			return
		}
	} else {
		data, err := httputil.DumpRequest(req, true)
		if err != nil {
			s.cfg.Handler.LogError("dump request failed" + errInfo(req.RemoteAddr, err))
			return
		}
		_, err = remote.Write(data)
		if err != nil {
			s.cfg.Handler.LogError("forward request failed" + errInfo(req.RemoteAddr, err))
			return
		}
	}
	s.cfg.Handler.Forward(conn, remote)
}

func replyOK(w net.Conn) error {
	resp := http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	return resp.Write(w)
}

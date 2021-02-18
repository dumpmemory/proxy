package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/lwch/proxy/addr"
)

// ClientConf client config
type ClientConf struct {
	ServerAddr   string        // Default: 127.0.0.1:1080
	ReadTimeout  time.Duration // Default: 1s
	WriteTimeout time.Duration // Default: 1s
}

// SetDefault check and set default value
func (cfg *ClientConf) SetDefault() {
	if len(cfg.ServerAddr) == 0 {
		cfg.ServerAddr = "127.0.0.1:1080"
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = time.Second
	}
}

// Client socks5 client
type Client struct {
	cfg    ClientConf
	server *net.TCPAddr
}

// NewClient create client
func NewClient(cfg ClientConf) (*Client, error) {
	cfg.SetDefault()
	addr, err := net.ResolveTCPAddr("tcp", cfg.ServerAddr)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:    cfg,
		server: addr,
	}, nil
}

// Dial connect address and reply connection
func (c *Client) Dial(addr string) (net.Conn, error) {
	return c.DialUserPass(addr, "", "")
}

func waitHandshakeResponse(conn net.Conn, timeout time.Duration) (Method, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var buf [2]byte
	_, err := io.ReadFull(conn, buf[:])
	if err != nil {
		return MethodNotSupport, err
	}
	if buf[0] != VERSION {
		return MethodNotSupport, ErrVersion
	}
	return Method(buf[1]), nil
}

func (c *Client) handshakeUserPass(conn net.Conn, user, pass string) error {
	if len(user) >= 255 {
		user = user[:255]
	}
	if len(pass) >= 255 {
		pass = pass[:255]
	}
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	err := writeTimeout(conn, buf, c.cfg.WriteTimeout)
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout))
	var rep [2]byte
	_, err = io.ReadFull(conn, rep[:])
	if err != nil {
		return err
	}
	if rep[0] != 0x01 {
		return fmt.Errorf("invalid auth version: %d", rep[0])
	}
	if rep[1] != 0 {
		return fmt.Errorf("invalid auth")
	}
	return nil
}

func (c *Client) request(conn net.Conn, a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("split host:port: %v", err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("parse port: %v", err)
	}
	reqAddr := addr.Addr{Port: uint16(p)}
	ip := net.ParseIP(host)
	if ip == nil {
		reqAddr.Type = addr.Domain
		reqAddr.Domain = host
	} else if len(ip) == net.IPv4len {
		reqAddr.Type = addr.IPV4
		reqAddr.IP = ip
	} else {
		reqAddr.Type = addr.IPV6
		reqAddr.IP = ip
	}
	err = writeTimeout(conn, append([]byte{VERSION, byte(CmdConnect), 0x00},
		reqAddr.Bytes()...), c.cfg.WriteTimeout)
	if err != nil {
		return fmt.Errorf("send connect: %v", err)
	}
	var hdr [4]byte
	conn.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout))
	_, err = io.ReadFull(conn, hdr[:])
	if err != nil {
		return fmt.Errorf("read response header: %v", err)
	}
	if hdr[0] != VERSION {
		return ErrVersion
	}
	if hdr[1] != byte(ReplyOK) {
		return fmt.Errorf("connect: %s", Reply(hdr[1]).String())
	}
	switch addr.Type(hdr[3]) {
	case addr.IPV4:
		var addrPort [net.IPv4len + 2]byte
		_, err = io.ReadFull(conn, addrPort[:])
	case addr.IPV6:
		var addrPort [net.IPv6len + 2]byte
		_, err = io.ReadFull(conn, addrPort[:])
	case addr.Domain:
		var l [1]byte
		_, err = conn.Read(l[:])
		if err != nil {
			return errors.New("read domain length")
		}
		domain := make([]byte, l[0]+2)
		_, err = io.ReadFull(conn, domain[:])
	default:
		return errors.New("response unknown address")
	}
	if err != nil {
		return fmt.Errorf("read addr: %v", err)
	}
	return nil
}

// DialUserPass connect address with user/pass and reply connection
func (c *Client) DialUserPass(addr, user, pass string) (net.Conn, error) {
	conn, err := net.DialTCP("tcp", nil, c.server)
	if err != nil {
		return nil, fmt.Errorf("connect: %v", err)
	}
	var wantMethod Method
	if len(user) != 0 || len(pass) != 0 {
		err = writeTimeout(conn, []byte{VERSION, 1, byte(MethodUserPass)}, c.cfg.WriteTimeout)
		wantMethod = MethodUserPass
	} else {
		err = writeTimeout(conn, []byte{VERSION, 1, byte(MethodNoAuth)}, c.cfg.WriteTimeout)
		wantMethod = MethodNoAuth
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %v", err)
	}
	method, err := waitHandshakeResponse(conn, c.cfg.ReadTimeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("wait handshake: %v", err)
	}
	if method != wantMethod {
		conn.Close()
		return nil, ErrMethod
	}
	if method == MethodUserPass {
		err = c.handshakeUserPass(conn, user, pass)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("handshake user/pass: %v", err)
		}
	}
	err = c.request(conn, addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("request: %v", err)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

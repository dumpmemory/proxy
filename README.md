# proxy

[![Go Reference](https://pkg.go.dev/badge/github.com/lwch/proxy.svg)](https://pkg.go.dev/github.com/lwch/proxy)

proxy library supported http(s) and socks5 protocol.

## http

https://tools.ietf.org/html/rfc7230#section-5.7.2

supported user/pass authentication.
  - ServerConf.Check: set true.
  - ServerHandler.CheckUserPass: check input user/pass is valid.

supported https proxy with set `ServerConf.Key` and `ServerConf.Crt` field.

### server example

    var cfg proxy.ServerConf
    // cfg.Key = "server.key"
    // cfg.Crt = "server.crt"
    svr := proxy.NewServer(cfg, ":1080")
    assert(svr.ListenAndServe())
    // assert(svr.ListenAndServeTLS())

### client example

    req, err := http.NewRequest("GET", "http://myip.ipip.net", nil)
    assert(err)
    httpCli := &http.Client{
        Transport: &http.Transport{
            Proxy: func(req *http.Request) (*url.URL, error) {
                return url.Parse("http://127.0.0.1:1080")
            },
            // TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
    rep, err := httpCli.Do(req)
    assert(err)
    defer rep.Body.Close()
    data, _ := ioutil.ReadAll(rep.Body)
    fmt.Print(string(data))

## socks5

https://tools.ietf.org/html/rfc1928

supported user/pass authentication.
  - ServerHandler.Handshake: check input supported socks5.MethodUserPass and return that.
  - ServerHandler.CheckUserPass: check input user/pass is valid.
  - Client.DialUserPass: dial connection by user/pass.

### server example

    var cfg socks5.ServerConf
    svr := socks5.NewServer(cfg)
    svr.ListenAndServe(":1080")

### client example

    var cfg socks5.ClientConf
    cli, err := socks5.NewClient(cfg)
    if err != nil {
        panic(err)
    }
    req, err := http.NewRequest("GET", "http://myip.ipip.net", nil)
    if err != nil {
        panic(err)
    }
    httpCli := &http.Client{
        Transport: &http.Transport{
            Dial: func(network, addr string) (net.Conn, error) {
                return cli.Dial(addr)
            },
        },
    }
    rep, err := httpCli.Do(req)
    if err != nil {
        panic(err)
    }
    defer rep.Body.Close()
    data, _ := ioutil.ReadAll(rep.Body)
    fmt.Print(string(data))
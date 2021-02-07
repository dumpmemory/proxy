# socks5

socks5 library supported no auth and user/pass authentication.

## server example

    var cfg socks5.ServerConf
    svr := socks5.NewServer(cfg)
    svr.ListenAndServe(":1080")

## client example

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
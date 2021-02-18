package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/lwch/socks5"
)

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	go func() {
		var cfg socks5.ServerConf
		svr := socks5.NewServer(cfg)
		assert(svr.ListenAndServe(":1080"))
	}()

	time.Sleep(time.Second)
	var cfg socks5.ClientConf
	cfg.ServerAddr = "127.0.0.1:1080"
	cli, err := socks5.NewClient(cfg)
	assert(err)
	req, err := http.NewRequest("GET", "http://myip.ipip.net", nil)
	assert(err)
	httpCli := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return cli.Dial(addr)
			},
		},
	}
	rep, err := httpCli.Do(req)
	assert(err)
	defer rep.Body.Close()
	data, _ := ioutil.ReadAll(rep.Body)
	fmt.Print(string(data))
}

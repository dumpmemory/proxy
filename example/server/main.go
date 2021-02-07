package main

import "github.com/lwch/socks5"

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	var cfg socks5.ServerConf
	svr := socks5.NewServer(cfg)
	assert(svr.ListenAndServe(":1080"))
}

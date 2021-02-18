package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	proxy "github.com/lwch/proxy/http"
)

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	go func() {
		var cfg proxy.ServerConf
		svr := proxy.NewServer(cfg, ":1080")
		assert(svr.ListenAndServe())
	}()

	time.Sleep(time.Second)
	req, err := http.NewRequest("GET", "http://myip.ipip.net", nil)
	assert(err)
	httpCli := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://127.0.0.1:1080")
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	rep, err := httpCli.Do(req)
	assert(err)
	defer rep.Body.Close()
	data, _ := ioutil.ReadAll(rep.Body)
	fmt.Print(string(data))
}

package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/codingeasygo/pdservice/discover"
	"github.com/codingeasygo/util/xprop"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		fmt.Printf("dockerdiscover %v version\n", Version)
		return
	}
	confPath := "conf/dockerdiscover.properties"
	if len(os.Args) > 1 {
		confPath = os.Args[1]
	}
	cfg := xprop.NewConfig()
	cfg.Load(confPath)
	cfg.Print()
	hostAddr := cfg.StrDef("127.0.0.1", "proxy_host_addr")
	hostName := cfg.StrDef("", "proxy_host_name")
	dockerCert := cfg.StrDef("certs", "docker_cert")
	dockerHost := cfg.StrDef("tcp://127.0.0.1:2376", "docker_host")
	listenAddr := cfg.StrDef(":9231", "listen")
	refreshTime := cfg.Int64Def(10000, "refresh_time")
	triggerAdded := cfg.StrDef("", "trigger_added")
	triggerRemoved := cfg.StrDef("", "trigger_removed")
	triggerBash := cfg.StrDef("bash", "trigger_bash")
	server, err := discover.NewDiscoverWithConf(dockerCert, dockerHost, hostAddr, hostName)
	if err != nil {
		panic(err)
	}
	server.Bash = triggerBash
	server.StartRefresh(time.Duration(refreshTime)*time.Millisecond, triggerAdded, triggerRemoved)
	err = http.ListenAndServe(listenAddr, server)
	if err != nil {
		panic(err)
	}
}

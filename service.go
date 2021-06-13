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
	err := cfg.Load(confPath)
	if err != nil {
		panic(err)
	}
	cfg.Print()
	listenAddr := cfg.StrDef(":9231", "listen")
	refreshTime := cfg.Int64Def(10000, "refresh_time")
	triggerAdded := cfg.StrDef("", "trigger_added")
	triggerRemoved := cfg.StrDef("", "trigger_removed")
	server := discover.NewDiscover()
	server.TriggerBash = cfg.StrDef("bash", "trigger_bash")
	server.DockerFinder = cfg.StrDef("", "trigger_finder")
	server.DockerCert = cfg.StrDef("certs", "docker_cert")
	server.DockerAddr = cfg.StrDef("tcp://127.0.0.1:2376", "docker_addr")
	server.DockerHost = cfg.StrDef("127.0.0.1", "docker_host")
	server.HostSuff = cfg.StrDef("", "host_suffix")
	server.StartRefresh(time.Duration(refreshTime)*time.Millisecond, triggerAdded, triggerRemoved)
	err = http.ListenAndServe(listenAddr, server)
	if err != nil {
		panic(err)
	}
}

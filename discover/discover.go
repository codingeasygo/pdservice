package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/util/debug"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/tlsconfig"
)

type Container struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Address *url.URL `json:"address"`
	Index   int      `json:"index"`
	Port    string   `json:"port"`
}

func (c *Container) HostPrefix() string {
	if c.Index == 0 {
		return fmt.Sprintf("%v.%v", strings.ReplaceAll(c.Version, ".", ""), c.Name)
	}
	return fmt.Sprintf("%v.%v%v", strings.ReplaceAll(c.Version, ".", ""), c.Name, c.Index)
}

type Discover struct {
	Client     *client.Client
	MatchKey   string
	HostAddr   string
	HostName   string
	Bash       string
	proxyList  []*Container
	proxyMap   map[string]*httputil.ReverseProxy
	proxyLock  sync.RWMutex
	refreshing bool
}

func NewDiscover(cli *client.Client, hostAddr, hostName string) (discover *Discover) {
	discover = &Discover{
		Client:    cli,
		MatchKey:  "-srv-",
		HostAddr:  hostAddr,
		HostName:  hostName,
		Bash:      "bash",
		proxyMap:  map[string]*httputil.ReverseProxy{},
		proxyLock: sync.RWMutex{},
	}
	return
}

func NewDiscoverWithConf(dockerCert, dockerHost, hostAddr, hostName string) (discover *Discover, err error) {
	options := tlsconfig.Options{
		CAFile:   filepath.Join(dockerCert, "ca.pem"),
		CertFile: filepath.Join(dockerCert, "cert.pem"),
		KeyFile:  filepath.Join(dockerCert, "key.pem"),
	}
	tlsc, err := tlsconfig.Client(options)
	if err != nil {
		return
	}
	httpClient := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: tlsc},
		CheckRedirect: client.CheckRedirect,
	}
	cli, err := client.NewClientWithOpts(client.WithHTTPClient(httpClient), client.WithHost(dockerHost))
	if err != nil {
		return
	}
	discover = NewDiscover(cli, hostAddr, hostName)
	return
}

func (d *Discover) Refresh() (all, added, removed []*Container, err error) {
	all, err = d.Discove()
	if err != nil {
		return
	}
	for _, having := range all {
		found := false
		for _, old := range d.proxyList {
			if having.HostPrefix() == old.HostPrefix() {
				found = true
				break
			}
		}
		if !found {
			added = append(added, having)
		}
	}
	for _, old := range d.proxyList {
		found := false
		for _, having := range all {
			if having.HostPrefix() == old.HostPrefix() {
				found = true
				break
			}
		}
		if !found {
			removed = append(removed, old)
		}
	}
	d.proxyLock.Lock()
	defer d.proxyLock.Unlock()
	d.proxyList = all
	for _, service := range removed {
		host := service.HostPrefix() + d.HostName
		delete(d.proxyMap, host)
	}
	for _, service := range added {
		host := service.HostPrefix() + d.HostName
		proxy := httputil.NewSingleHostReverseProxy(service.Address)
		d.proxyMap[host] = proxy
	}
	return
}

func (d *Discover) Discove() (containers []*Container, err error) {
	containerList, err := d.Client.ContainerList(context.Background(), types.ContainerListOptions{
		Filters: filters.NewArgs(filters.Arg("name", fmt.Sprintf("^.*%vv[0-9\\.]*$", d.MatchKey))),
	})
	if err != nil {
		return
	}
	for _, c := range containerList {
		if c.State != "running" {
			continue
		}
		inspect, xerr := d.Client.ContainerInspect(context.Background(), c.ID)
		if xerr != nil {
			err = xerr
			return
		}
		name := strings.TrimPrefix(inspect.Name, "/")
		nameParts := strings.SplitN(name, d.MatchKey, 2)
		index := 0
		for private, ports := range inspect.NetworkSettings.Ports {
			address, _ := url.Parse(fmt.Sprintf("http://%v:%v", d.HostAddr, ports[0].HostPort))
			container := &Container{
				Name:    nameParts[0],
				Version: nameParts[1],
				Address: address,
				Index:   index,
				Port:    private.Port(),
			}
			containers = append(containers, container)
			index++
		}
	}
	return
}

func (d *Discover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.proxyLock.RLock()
	proxy := d.proxyMap[r.Host]
	d.proxyLock.RUnlock()
	if proxy == nil {
		http.NotFound(w, r)
	} else {
		proxy.ServeHTTP(w, r)
	}
}

func (d *Discover) StartRefresh(refreshTime time.Duration, onAdded, onRemoved string) {
	d.refreshing = true
	InfoLog("start refresh by time:%v,added:%v,removed:%v", refreshTime, onAdded, onRemoved)
	go d.runRefresh(refreshTime, onAdded, onRemoved)
}

func (d *Discover) StopRefresh() {
	d.refreshing = false
}

func (d *Discover) runRefresh(refreshTime time.Duration, onAdded, onRemoved string) {
	for d.refreshing {
		d.callRefresh(onAdded, onRemoved)
		time.Sleep(refreshTime)
	}
}

func (d *Discover) callRefresh(onAdded, onRemoved string) {
	defer func() {
		if xerr := recover(); xerr != nil {
			ErrorLog("call refresh panic with %v, call stack is:\n%v", xerr, debug.CallStatck())
		}
	}()
	all, added, removed, err := d.Refresh()
	if err != nil {
		ErrorLog("call refresh fail with %v", err)
		return
	}
	DebugLog("call refresh success with all:%v,added:%v,removed:%v", len(all), len(added), len(removed))
	if len(added) > 0 && len(onAdded) > 0 {
		d.callTrigger(added, "added", onAdded)
	}
	if len(removed) > 0 && len(onRemoved) > 0 {
		d.callTrigger(removed, "removed", onRemoved)
	}
}

func (d *Discover) callTrigger(services []*Container, name, trigger string) {
	for _, service := range services {
		cmd := exec.Command(d.Bash, trigger)
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_VER", service.Version))
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_NAME", service.Name))
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_INDEX", service.Index))
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_HOST", service.Address.Host))
		cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_PREF", service.HostPrefix()))
		info, xerr := cmd.Output()
		if xerr != nil {
			WarnLog("call refresh trigger %v fail with %v by\n\tCMD:%v\n\tENV:%v\n\tOut:\n%v", name, xerr, cmd.Path, cmd.Env, string(info))
		} else {
			InfoLog("call refresh trigger %v success by\n\tCMD:%v\n\tENV:%v\n\tOut:\n%v", name, cmd.Path, cmd.Env, string(info))
		}
	}
}

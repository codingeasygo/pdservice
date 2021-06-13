package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

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
	Client    *client.Client
	MatchKey  string
	HostAddr  string
	HostName  string
	proxyList []*Container
	proxyMap  map[string]*httputil.ReverseProxy
	proxyLock sync.RWMutex
}

func NewDiscover(cli *client.Client, hostAddr, hostName string) (discover *Discover) {
	discover = &Discover{
		Client:    cli,
		MatchKey:  "-srv-",
		HostAddr:  hostAddr,
		HostName:  hostName,
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

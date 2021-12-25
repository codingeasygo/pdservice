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
	"github.com/codingeasygo/util/xprop"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/tlsconfig"
	"golang.org/x/net/websocket"
)

type Container struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Address *url.URL `json:"-"`
	Index   int      `json:"index"`
	Port    string   `json:"port"`
	Token   string   `json:"token"`
}

func (c *Container) HostPrefix() string {
	if c.Index == 0 {
		return fmt.Sprintf("%v.%v", strings.ReplaceAll(c.Version, ".", ""), c.Name)
	}
	return fmt.Sprintf("%v.%v%v", strings.ReplaceAll(c.Version, ".", ""), c.Name, c.Index)
}

type Discover struct {
	MatchKey     string
	DockerFinder string
	DockerCert   string
	DockerAddr   string
	DockerHost   string
	HostSuff     string
	TriggerBash  string
	SrvPrefix    string
	clientNew    *client.Client
	clientHost   string
	clientLatest time.Time
	clientLock   sync.RWMutex
	proxyList    []*Container
	proxyAll     map[string]*Container
	proxyReverse map[string]*httputil.ReverseProxy
	proxyLock    sync.RWMutex
	refreshing   bool
}

func NewDiscover() (discover *Discover) {
	discover = &Discover{
		MatchKey:     "-srv-",
		TriggerBash:  "bash",
		SrvPrefix:    "/_s/",
		clientLock:   sync.RWMutex{},
		proxyAll:     map[string]*Container{},
		proxyReverse: map[string]*httputil.ReverseProxy{},
		proxyLock:    sync.RWMutex{},
	}
	return
}

func (d *Discover) newDockerClient() (cli *client.Client, remoteHost string, err error) {
	d.clientLock.Lock()
	defer d.clientLock.Unlock()
	if d.clientNew != nil && time.Since(d.clientLatest) < 10*time.Minute {
		cli, remoteHost = d.clientNew, d.clientHost
		return
	}
	if d.clientNew != nil {
		d.clientNew.Close()
		d.clientNew = nil
	}
	dockerCert, dockerAddr := d.DockerCert, d.DockerAddr
	remoteHost = d.DockerHost
	if len(d.DockerFinder) > 0 {
		info, xerr := exec.Command(d.TriggerBash, d.DockerFinder).Output()
		if xerr != nil {
			err = xerr
			return
		}
		conf := xprop.NewConfig()
		err = conf.LoadPropString(string(info))
		if err != nil {
			return
		}
		dockerCert = conf.StrDef(dockerCert, "docker_cert")
		dockerAddr = conf.StrDef(dockerAddr, "docker_addr")
		remoteHost = conf.StrDef(d.DockerHost, "docker_host")
	}
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
	cli, err = client.NewClientWithOpts(client.WithHTTPClient(httpClient), client.WithHost(dockerAddr))
	if err == nil {
		d.clientNew = cli
		d.clientHost = remoteHost
		d.clientLatest = time.Now()
	}
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
				old.ID = having.ID
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
		host := service.HostPrefix() + d.HostSuff
		delete(d.proxyAll, host)
		delete(d.proxyReverse, host)
		InfoLog("Discover remove %v for service down", host)
	}
	for _, service := range added {
		host := service.HostPrefix() + d.HostSuff
		proxy := httputil.NewSingleHostReverseProxy(service.Address)
		d.proxyAll[host] = service
		d.proxyReverse[host] = proxy
		InfoLog("Discover add %v for service up", host)
	}
	return
}

func (d *Discover) Discove() (containers []*Container, err error) {
	cli, remoteHost, err := d.newDockerClient()
	if err != nil {
		return
	}
	containerList, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", fmt.Sprintf("^.*%vv[0-9\\.]*.*$", d.MatchKey))),
	})
	if err != nil {
		return
	}
	for _, c := range containerList {
		inspect, xerr := cli.ContainerInspect(context.Background(), c.ID)
		if xerr != nil {
			err = xerr
			return
		}
		name := strings.TrimPrefix(inspect.Name, "/")
		nameParts := strings.SplitN(name, d.MatchKey, 2)
		verParts := strings.SplitN(nameParts[1], "-", 2)
		index := 0
		if len(inspect.NetworkSettings.Ports) < 1 {
			address, _ := url.Parse(fmt.Sprintf("http://%v:%v", remoteHost, 1))
			container := &Container{
				ID:      c.ID,
				Name:    nameParts[0],
				Version: verParts[0],
				Address: address,
				Index:   index,
				Port:    "1",
			}
			if len(verParts) > 1 {
				container.Token = verParts[1]
			}
			containers = append(containers, container)
			continue
		}
		for private, ports := range inspect.NetworkSettings.Ports {
			address, _ := url.Parse(fmt.Sprintf("http://%v:%v", remoteHost, ports[0].HostPort))
			container := &Container{
				ID:      c.ID,
				Name:    nameParts[0],
				Version: verParts[0],
				Address: address,
				Index:   index,
				Port:    private.Port(),
			}
			if len(verParts) > 1 {
				container.Token = verParts[1]
			}
			containers = append(containers, container)
			index++
		}
	}
	return
}

func (d *Discover) procDockerLogs(w http.ResponseWriter, r *http.Request, service *Container) {
	proc := func(c *websocket.Conn) {
		defer c.Close()
		cli, _, err := d.newDockerClient()
		if err != nil {
			WarnLog("proc %v coitainer log fail with %v", service.Name, err)
			fmt.Fprintf(c, "new docker client fail with %v", err)
			return
		}
		reader, err := cli.ContainerLogs(context.Background(), service.ID, types.ContainerLogsOptions{
			ShowStdout: r.Form.Get("stdout") != "0",
			ShowStderr: r.Form.Get("stderr") != "0",
			Since:      r.Form.Get("since"),
			Until:      r.Form.Get("until"),
			Timestamps: r.Form.Get("timestamps") == "1",
			Follow:     r.Form.Get("follow") == "1",
			Tail:       r.Form.Get("tail"),
			Details:    r.Form.Get("details") == "1",
		})
		if err != nil {
			WarnLog("proc %v coitainer log fail with %v", service.Name, err)
			fmt.Fprintf(c, "proc docker log fail with %v", err)
			return
		}
		stdcopy.StdCopy(c, c, reader)
	}
	wsService := websocket.Server{
		Handler: proc,
	}
	r.ParseForm()
	wsService.ServeHTTP(w, r)
}

func (d *Discover) procDockerControl(w http.ResponseWriter, r *http.Request, service *Container, action string) {
	cli, _, err := d.newDockerClient()
	if err != nil {
		WarnLog("proc %v coitainer restart fail with %v", service.Name, err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "new docker client fail with %v", err)
		return
	}
	timeout := 10 * time.Second
	result := ""
	switch action {
	case "docker/start":
		err = cli.ContainerStart(context.Background(), service.ID, types.ContainerStartOptions{})
		result = "ok"
	case "docker/stop":
		err = cli.ContainerStop(context.Background(), service.ID, &timeout)
		result = "ok"
	case "docker/restart":
		err = cli.ContainerRestart(context.Background(), service.ID, &timeout)
		result = "ok"
	case "docker/ps":
		var info types.ContainerJSON
		info, err = cli.ContainerInspect(context.Background(), service.ID)
		if err == nil {
			result = fmt.Sprintf("%v\t%v\t%v\t%v\n", strings.TrimPrefix(info.Name, "/"), info.Config.Image, info.Created, info.State.Status)
		}
	}
	if err != nil {
		WarnLog("proc %v coitainer restart fail with %v", service.Name, err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "proc docker log fail with %v", err)
		return
	}
	fmt.Fprintf(w, "%v", result)
}

func (d *Discover) procServer(w http.ResponseWriter, r *http.Request, service *Container) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "unauthorized")
		return
	}
	if username != service.Name || password != service.Token {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "invalid password")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, d.SrvPrefix)
	path = strings.Trim(path, "/")
	switch path {
	case "docker/logs":
		d.procDockerLogs(w, r, service)
	case "docker/start", "docker/stop", "docker/restart", "docker/ps":
		d.procDockerControl(w, r, service, path)
	default:
		http.NotFound(w, r)
	}
}

func (d *Discover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.proxyLock.RLock()
	service := d.proxyAll[r.Host]
	reverse := d.proxyReverse[r.Host]
	d.proxyLock.RUnlock()
	if service != nil && reverse != nil {
		if strings.HasPrefix(r.URL.Path, d.SrvPrefix) {
			d.procServer(w, r, service)
		} else {
			reverse.ServeHTTP(w, r)
		}
		return
	}
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "%v not found\n\n", r.Host)
	d.proxyLock.RLock()
	fmt.Fprintf(w, "Having:\n")
	for having := range d.proxyAll {
		fmt.Fprintf(w, "\t%v\n", having)
	}
	d.proxyLock.RUnlock()
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
		cmd := exec.Command(d.TriggerBash, trigger)
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

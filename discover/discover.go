package discover

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codingeasygo/util/converter"
	"github.com/codingeasygo/util/debug"
	"github.com/codingeasygo/util/xprop"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-connections/tlsconfig"
	"golang.org/x/net/websocket"
)

func copyAndClose(src, dst net.Conn) {
	io.Copy(dst, src)
	dst.Close()
}

type Forward struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Type   string `json:"type"`
	Prefix string `json:"prefix"`
	URI    string `json:"uri"`
}

func (f *Forward) NewReverseProxy() (proxy *httputil.ReverseProxy, err error) {
	remote, err := url.Parse(fmt.Sprintf("http://%v", f.URI))
	if err == nil {
		proxy = httputil.NewSingleHostReverseProxy(remote)
	}
	return
}

type Container struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	Token    string              `json:"token"`
	Forwards map[string]*Forward `json:"forwards"`
}

type ReverseProxy struct {
	Reverse *httputil.ReverseProxy
	Service *Container
}

type ListenerProxy struct {
	TCP     net.Listener
	UDP     *net.UDPConn
	Service *Container
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
	proxyAll     map[string]*Container
	proxyReverse map[string]*ReverseProxy
	proxyListen  map[string]*ListenerProxy
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
		proxyReverse: map[string]*ReverseProxy{},
		proxyListen:  map[string]*ListenerProxy{},
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
			ErrorLog("Discover call finder fail with %v by bash:%v,finder:%v", err, d.TriggerBash, d.DockerFinder)
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

func (d *Discover) Refresh() (all, added, updated, removed map[string]*Container, err error) {
	all, err = d.Discove()
	if err != nil {
		return
	}
	d.proxyLock.Lock()
	defer d.proxyLock.Unlock()
	added = map[string]*Container{}
	updated = map[string]*Container{}
	removed = map[string]*Container{}
	oldAll := d.proxyAll
	newAll := map[string]*Container{}
	procReverse := func(newForward *Forward, service *Container) {
		host := newForward.Prefix + d.HostSuff
		if old, ok := oldAll[newForward.Prefix]; ok {
			if oldForward, ok := old.Forwards[newForward.Prefix]; ok && oldForward.URI != newForward.URI { //updated
				proxy, xerr := newForward.NewReverseProxy()
				if xerr != nil {
					WarnLog("Discover update %v for service updated fail with %v", host, xerr)
					return
				}
				d.proxyReverse[host] = &ReverseProxy{Reverse: proxy, Service: service}
				updated[newForward.Prefix] = service
				InfoLog("Discover update %v for service updated", host)
			}
		} else { //new
			proxy, xerr := newForward.NewReverseProxy()
			if xerr != nil {
				WarnLog("Discover update %v for service up fail with %v", host, xerr)
				return
			}
			d.proxyReverse[host] = &ReverseProxy{Reverse: proxy, Service: service}
			added[newForward.Prefix] = service
			InfoLog("Discover add %v for service up", host)
		}
		newAll[newForward.Prefix] = service
	}
	removeReverse := func(oldForward *Forward, service *Container) {
		host := oldForward.Prefix + d.HostSuff
		if _, ok := all[oldForward.Prefix]; !ok { //deleted
			delete(d.proxyReverse, host)
			removed[oldForward.Prefix] = service
			InfoLog("Discover remove %v for service down", host)
		}
	}
	procListen := func(newForward *Forward, service *Container) {
		if old, ok := oldAll[newForward.Prefix]; ok {
			if oldForward, ok := old.Forwards[newForward.Prefix]; ok && oldForward.URI == newForward.URI { //updated
				newAll[newForward.Prefix] = service
				return
			}
		}
		switch newForward.Type {
		case "tcp":
			if d.removeTCP(newForward) {
				updated[newForward.Prefix] = service
			} else {
				added[newForward.Prefix] = service
			}
			go d.procTCP(newForward, service)
			newAll[newForward.Prefix] = service
		case "udp":
			if d.removeUDP(newForward) {
				updated[newForward.Prefix] = service
			} else {
				added[newForward.Prefix] = service
			}
			go d.procUDP(newForward, service)
			newAll[newForward.Prefix] = service
		}
	}
	removeListen := func(oldForward *Forward, service *Container) {
		switch oldForward.Type {
		case "tcp":
			removed[oldForward.Prefix] = service
			d.removeTCP(oldForward)
		case "udp":
			removed[oldForward.Prefix] = service
			d.removeUDP(oldForward)
		}
	}
	for prefix, service := range all {
		if newForward, ok := service.Forwards[prefix]; ok {
			switch newForward.Type {
			case "http":
				procReverse(newForward, service)
			case "tcp", "udp":
				procListen(newForward, service)
			}
		}
	}
	for prefix, service := range oldAll {
		if _, ok := newAll[prefix]; ok {
			continue
		}
		if oldForward, ok := service.Forwards[prefix]; ok {
			switch oldForward.Type {
			case "http":
				removeReverse(oldForward, service)
			case "tcp", "udp":
				removeListen(oldForward, service)
			}
		}
	}
	d.proxyAll = newAll
	return
}

func (d *Discover) Discove() (containers map[string]*Container, err error) {
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
	containers = map[string]*Container{}
	for _, c := range containerList {
		if c.State != "running" {
			continue
		}
		inspect, xerr := cli.ContainerInspect(context.Background(), c.ID)
		if xerr != nil {
			err = xerr
			return
		}
		name := strings.TrimPrefix(inspect.Name, "/")
		nameParts := strings.SplitN(name, d.MatchKey, 2)
		verParts := strings.SplitN(nameParts[1], "-", 2)
		container := &Container{
			ID:       c.ID,
			Name:     nameParts[0],
			Version:  verParts[0],
			Forwards: map[string]*Forward{},
		}
		for key, val := range inspect.Config.Labels {
			if key == "PD_SERVICE_TOKEN" {
				container.Token = val
				continue
			}
			var forward *Forward
			if strings.HasPrefix(key, "PD_HOST_") {
				hostKey := ""
				portVal := ""
				valParts := strings.SplitN(val, "/", 2)
				if len(valParts) == 2 {
					hostKey = valParts[0]
					portVal = valParts[1]
				} else {
					portVal = valParts[0]
				}
				portKey := fmt.Sprintf("%v/tcp", strings.TrimPrefix(portVal, ":"))
				portMap := inspect.NetworkSettings.Ports[nat.Port(portKey)]
				if portMap == nil {
					WarnLog("Discover parse container %v lable %v=%v fail with %v, all is %v", name, key, val, "port is not found", converter.JSON(inspect.NetworkSettings.Ports))
					continue
				}
				hostPort := portMap[0].HostPort
				forward = &Forward{
					Name: strings.TrimPrefix(key, "PD_HOST_"),
					Type: "http",
					Key:  hostKey,
					URI:  fmt.Sprintf("%v:%v", remoteHost, hostPort),
				}
				if len(hostKey) > 0 {
					forward.Prefix = fmt.Sprintf("%v.%v.%v", hostKey, strings.ReplaceAll(container.Version, ".", ""), container.Name)
				} else {
					forward.Prefix = fmt.Sprintf("%v.%v", strings.ReplaceAll(container.Version, ".", ""), container.Name)
				}
			} else if strings.HasPrefix(key, "PD_TCP_") || strings.HasPrefix(key, "PD_UDP_") {
				valParts := strings.SplitN(val, "/", 2)
				if len(valParts) != 2 {
					WarnLog("Discover parse container %v lable %v=%v fail with %v, all is %v", name, key, val, "value is invalid", converter.JSON(inspect.NetworkSettings.Ports))
					continue
				}
				hostKey := valParts[0]
				portVal := valParts[1]
				portKey := fmt.Sprintf("%v/tcp", strings.TrimPrefix(portVal, ":"))
				portMap := inspect.NetworkSettings.Ports[nat.Port(portKey)]
				if portMap == nil {
					WarnLog("Discover parse container %v lable %v=%v fail with %v, all is %v", name, key, val, "port is not found", converter.JSON(inspect.NetworkSettings.Ports))
					continue
				}
				hostPort := portMap[0].HostPort
				forward = &Forward{
					Key: hostKey,
					URI: fmt.Sprintf("%v:%v", remoteHost, hostPort),
				}
				if strings.HasPrefix(key, "PD_TCP_") {
					forward.Name = strings.TrimPrefix(key, "PD_TCP_")
					forward.Type = "tcp"
				} else {
					forward.Name = strings.TrimPrefix(key, "PD_UDP_")
					forward.Type = "udp"
				}
				forward.Prefix = fmt.Sprintf("%v://%v", forward.Type, forward.Key)
			}
			if forward != nil {
				container.Forwards[forward.Prefix] = forward
				containers[forward.Prefix] = container
			}
		}
	}
	return
}

func (d *Discover) procDockerLogs(w http.ResponseWriter, r *http.Request, service *Container, containerID string) {
	proc := func(c *websocket.Conn) {
		defer c.Close()
		cli, _, err := d.newDockerClient()
		if err != nil {
			WarnLog("Discover proc %v coitainer log fail with %v", service.Name, err)
			fmt.Fprintf(c, "new docker client fail with %v", err)
			return
		}
		reader, err := cli.ContainerLogs(context.Background(), containerID, types.ContainerLogsOptions{
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
			WarnLog("Discover proc %v coitainer log fail with %v", service.Name, err)
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

func (d *Discover) procDockerControl(w http.ResponseWriter, r *http.Request, service *Container, action, containerID string) {
	cli, _, err := d.newDockerClient()
	if err != nil {
		WarnLog("Discover proc %v coitainer restart fail with %v", service.Name, err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "new docker client fail with %v", err)
		return
	}
	failResult := func(err error) {
		WarnLog("Discover proc %v coitainer %v fail with %v", service.Name, action, err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "proc docker log fail with %v", err)
	}
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", service.Name)),
	})
	if err != nil {
		failResult(err)
		return
	}
	accessResult := func() bool {
		access := false
		for _, container := range containers {
			if container.ID == containerID || strings.TrimPrefix(container.Names[0], "/") == containerID {
				access = true
				break
			}
		}
		if !access {
			err = fmt.Errorf("not access")
			WarnLog("Discover proc %v coitainer %v fail with %v", service.Name, action, err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "proc docker log fail with %v", err)
		}
		return access
	}
	timeout := 10 * time.Second
	result := ""
	switch action {
	case "docker/start":
		if !accessResult() {
			return
		}
		err = cli.ContainerStart(context.Background(), containerID, types.ContainerStartOptions{})
		result = "ok"
	case "docker/stop":
		if !accessResult() {
			return
		}
		err = cli.ContainerStop(context.Background(), containerID, &timeout)
		result = "ok"
	case "docker/restart":
		if !accessResult() {
			return
		}
		err = cli.ContainerRestart(context.Background(), containerID, &timeout)
		result = "ok"
	case "docker/ps":
		result = ""
		for _, container := range containers {
			var info types.ContainerJSON
			info, err = cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				break
			}
			result += fmt.Sprintf("%v\t%v\t%v\t%v\t%v\n", container.ID, strings.TrimPrefix(info.Name, "/"), info.Config.Image, info.Created, info.State.Status)
		}
	}
	if err != nil {
		failResult(err)
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
	r.ParseForm()
	containerID := r.FormValue("id")
	if len(containerID) < 1 {
		containerID = service.ID
	}
	path := strings.TrimPrefix(r.URL.Path, d.SrvPrefix)
	path = strings.Trim(path, "/")
	switch path {
	case "docker/logs":
		d.procDockerLogs(w, r, service, containerID)
	case "docker/start", "docker/stop", "docker/restart", "docker/ps":
		d.procDockerControl(w, r, service, path, containerID)
	default:
		http.NotFound(w, r)
	}
}

func (d *Discover) removeUDP(forward *Forward) (removed bool) {
	if ln, ok := d.proxyListen[forward.Prefix]; ok {
		ln.UDP.Close()
		delete(d.proxyListen, forward.Prefix)
		removed = true
	}
	return
}

func (d *Discover) procUDP(forward *Forward, service *Container) (err error) {
	addr, err := net.ResolveUDPAddr(forward.Type, forward.Key)
	if err != nil {
		WarnLog("Discover forward %v://%v=>%v://%v is fail with %v", forward.Type, forward.Prefix, forward.Type, forward.URI, err)
		return
	}
	local, err := net.ListenUDP(forward.Type, addr)
	if err != nil {
		WarnLog("Discover forward %v://%v=>%v://%v is fail with %v", forward.Type, forward.Prefix, forward.Type, forward.URI, err)
		return
	}
	remote, err := net.Dial(forward.Type, forward.URI)
	if err != nil {
		WarnLog("Discover forward %v://%v=>%v://%v is fail with %v", forward.Type, forward.Prefix, forward.Type, forward.URI, err)
		return
	}
	InfoLog("Discover forward %v://%v=>%v://%v is started on %v", forward.Type, forward.Prefix, forward.Type, forward.URI, addr)
	d.proxyListen[forward.Prefix] = &ListenerProxy{UDP: local, Service: service}
	defer func() {
		remote.Close()
		local.Close()
		delete(d.proxyListen, forward.Prefix)
	}()
	go copyAndClose(local, remote)
	copyAndClose(remote, local)
	InfoLog("Discover forward %v://%v=>%v://%v is stopped", forward.Type, forward.Prefix, forward.Type, forward.URI)
	return
}

func (d *Discover) removeTCP(forward *Forward) (removed bool) {
	if ln, ok := d.proxyListen[forward.Prefix]; ok {
		ln.TCP.Close()
		delete(d.proxyListen, forward.Prefix)
		removed = true
	}
	return
}

func (d *Discover) procTCP(forward *Forward, service *Container) (err error) {
	ln, err := net.Listen(forward.Type, forward.Key)
	if err != nil {
		WarnLog("Discover forward %v://%v=>%v://%v is fail with %v", forward.Type, forward.Prefix, forward.Type, forward.URI, err)
		return
	}
	d.proxyListen[forward.Prefix] = &ListenerProxy{TCP: ln, Service: service}
	defer func() {
		ln.Close()
		delete(d.proxyListen, forward.Prefix)
	}()
	InfoLog("Discover forward %v://%v=>%v://%v is started on %v", forward.Type, forward.Prefix, forward.Type, forward.URI, ln.Addr())
	for {
		local, xerr := ln.Accept()
		if xerr != nil {
			err = xerr
			break
		}
		remote, xerr := net.Dial(forward.Type, forward.URI)
		if xerr != nil {
			WarnLog("Discover dial to %v://%v fail with %v", forward.Type, forward.URI, xerr)
			return
		}
		go copyAndClose(local, remote)
		go copyAndClose(remote, local)
	}
	InfoLog("Discover forward %v://%v=>%v://%v is stopped", forward.Type, forward.Prefix, forward.Type, forward.URI)
	return
}

func (d *Discover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.proxyLock.RLock()
	reverse := d.proxyReverse[r.Host]
	d.proxyLock.RUnlock()
	if reverse != nil {
		if strings.HasPrefix(r.URL.Path, d.SrvPrefix) {
			d.procServer(w, r, reverse.Service)
		} else {
			reverse.Reverse.ServeHTTP(w, r)
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
	InfoLog("Discover start refresh by time:%v,added:%v,removed:%v", refreshTime, onAdded, onRemoved)
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
			ErrorLog("Discover call refresh panic with %v, call stack is:\n%v", xerr, debug.CallStatck())
		}
	}()
	all, added, updated, removed, err := d.Refresh()
	if err != nil {
		ErrorLog("Discover call refresh fail with %v", err)
		return
	}
	DebugLog("Discover call refresh success with all:%v,added:%v,updated:%v,removed:%v", len(all), len(added), len(updated), len(removed))
	if len(added) > 0 && len(onAdded) > 0 {
		d.callTrigger(added, "added", onAdded)
	}
	if len(removed) > 0 && len(onRemoved) > 0 {
		d.callTrigger(removed, "removed", onRemoved)
	}
}

func (d *Discover) callTrigger(services map[string]*Container, name, trigger string) {
	for _, service := range services {
		for _, forward := range service.Forwards {
			cmd := exec.Command(d.TriggerBash, trigger)
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_VER", service.Version))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_NAME", service.Name))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_TYPE", forward.Type))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_HOST", forward.URI))
			cmd.Env = append(cmd.Env, fmt.Sprintf("%v=%v", "PD_SERVICE_PREF", forward.Prefix))
			info, xerr := cmd.Output()
			if xerr != nil {
				WarnLog("Discover call refresh trigger %v fail with %v by\n\tCMD:%v\n\tENV:%v\n\tOut:\n%v", name, xerr, cmd.Path, cmd.Env, string(info))
			} else {
				InfoLog("Discover call refresh trigger %v success by\n\tCMD:%v\n\tENV:%v\n\tOut:\n%v", name, cmd.Path, cmd.Env, string(info))
			}
		}
	}
}

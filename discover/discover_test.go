package discover

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codingeasygo/util/xnet"
)

func callScript(script string) string {
	tempFile, err := os.CreateTemp(os.TempDir(), "bash-*")
	if err != nil {
		panic(err)
	}
	tempFile.WriteString(script + "\n")
	tempFile.Close()
	cmd := exec.Command("bash", tempFile.Name())
	data, _ := cmd.Output()
	os.Remove(tempFile.Name())
	return strings.TrimSpace(string(data))
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func TestDiscover(t *testing.T) {
	{ //clear
		fmt.Println(callScript(`
			docker exec docker-discover docker rm -f ds-srv-v1.0.0
			docker exec docker-discover docker rm -f ds-srv-v1.0.1
			docker exec docker-discover docker rm -f ds-srv-v1.0.2
		`))
		time.Sleep(time.Millisecond * 10)
		fmt.Println(callScript(`
			docker exec docker-discover docker run -d --label PD_HOST=80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST=80 --name ds-srv-v1.0.1 --restart always -P nginx
		`))
	}
	pwd, _ := os.Getwd()
	dockerHost := callScript(`docker inspect --format="{{.NetworkSettings.IPAddress}}" docker-discover`)
	dockerCert := filepath.Join(pwd, "../test/certs/client")
	dockerAddr := fmt.Sprintf("tcp://%v:2376", dockerHost)
	hostSuff := ".test.loc"
	discover := NewDiscover()
	discover.HostSuff = hostSuff
	{
		fmt.Println("--> test container up")
		discover.DockerFinder = ""
		discover.DockerCert = dockerCert
		discover.DockerAddr = dockerAddr
		discover.DockerHost = dockerHost
		fmt.Println(callScript(`
			docker exec docker-discover docker start ds-srv-v1.0.0
			docker exec docker-discover docker start ds-srv-v1.0.1
		`))
		all, added, _, removed, err := discover.Refresh()
		if err != nil || len(all) != 2 || len(added) != 2 || len(removed) != 0 {
			fmt.Printf("all->%v\nadded->%v\nremoved-->%v\n\n", all, added, removed)
			t.Error(err)
			return
		}
		req1 := httptest.NewRequest("GET", "http://v100.ds.test.loc/", nil)
		res1 := httptest.NewRecorder()
		discover.ServeHTTP(res1, req1)
		if !strings.Contains(res1.Body.String(), "nginx") {
			t.Error(res1.Body.String())
			return
		}
		req2 := httptest.NewRequest("GET", "http://v101.ds.test.loc/", nil)
		res2 := httptest.NewRecorder()
		discover.ServeHTTP(res2, req2)
		if !strings.Contains(res2.Body.String(), "nginx") {
			t.Error(res2.Body.String())
			return
		}
		req3 := httptest.NewRequest("GET", "http://v102.ds.test.loc/", nil)
		res3 := httptest.NewRecorder()
		discover.ServeHTTP(res3, req3)
		if !strings.Contains(res3.Body.String(), "not found") {
			t.Error(res3.Body.String())
			return
		}
	}
	{
		fmt.Println("--> test container down")
		discover.DockerFinder = "./finder.sh"
		discover.DockerCert = ""
		discover.DockerAddr = ""
		discover.DockerHost = ""
		fmt.Println(callScript(`
			docker exec docker-discover docker stop ds-srv-v1.0.0
		`))
		all, added, updated, removed, err := discover.Refresh()
		if err != nil || len(all) != 1 || len(added) != 0 || len(updated) != 0 || len(removed) != 1 {
			fmt.Printf("all->%v\nadded->%v\nupdated-->%v\nremoved-->%v\n\n", all, added, updated, removed)
			t.Error(err)
			return
		}
		req1 := httptest.NewRequest("GET", "http://v100.ds.test.loc/", nil)
		res1 := httptest.NewRecorder()
		discover.ServeHTTP(res1, req1)
		if res1.Result().StatusCode != http.StatusBadGateway && res1.Result().StatusCode != http.StatusNotFound {
			t.Error(res1.Body.String())
			return
		}
		req2 := httptest.NewRequest("GET", "http://v101.ds.test.loc/", nil)
		res2 := httptest.NewRecorder()
		discover.ServeHTTP(res2, req2)
		if !strings.Contains(res2.Body.String(), "nginx") {
			t.Error(res2.Body.String())
			return
		}
	}
	{
		fmt.Println("--> test container multi host")
		discover.DockerFinder = ""
		discover.DockerCert = dockerCert
		discover.DockerAddr = dockerAddr
		discover.DockerHost = dockerHost
		fmt.Println(callScript(`
			docker exec docker-discover docker rm -f ds-srv-v1.0.0
			docker exec docker-discover docker rm -f ds-srv-v1.0.1
			docker exec docker-discover docker rm -f ds-srv-v1.0.2
		`))
		discover.Refresh()
		fmt.Println(callScript(`
			docker exec docker-discover docker run -d --label PD_HOST=80 --label PD_HOST_a0=80 --label PD_HOST_a1=80 --name ds-srv-v1.0.2 --restart always -P nginx
		`))
		time.Sleep(100 * time.Millisecond)
		all, added, updated, removed, err := discover.Refresh()
		if err != nil || len(all) != 3 || len(added) != 3 || len(updated) != 0 || len(removed) != 0 {
			fmt.Printf("all->%v\nadded->%v\nupdated-->%v\nremoved-->%v\n\n", all, added, updated, removed)
			t.Error(err)
			return
		}
		req1 := httptest.NewRequest("GET", "http://v102.ds.test.loc/", nil)
		res1 := httptest.NewRecorder()
		discover.ServeHTTP(res1, req1)
		if !strings.Contains(res1.Body.String(), "nginx") {
			t.Error(res1.Body.String())
			return
		}
		req2 := httptest.NewRequest("GET", "http://a0.v102.ds.test.loc/", nil)
		res2 := httptest.NewRecorder()
		discover.ServeHTTP(res2, req2)
		if !strings.Contains(res2.Body.String(), "nginx") {
			t.Error(res2.Body.String())
			return
		}
		req3 := httptest.NewRequest("GET", "http://a0.v102.ds.test.loc/", nil)
		res3 := httptest.NewRecorder()
		discover.ServeHTTP(res3, req3)
		if !strings.Contains(res2.Body.String(), "nginx") {
			t.Error(res2.Body.String())
			return
		}
	}
	{
		fmt.Println(callScript(`
			docker exec docker-discover docker rm -f ds-srv-v1.0.0
			docker exec docker-discover docker rm -f ds-srv-v1.0.1
			docker exec docker-discover docker rm -f ds-srv-v1.0.2
		`))
		discover.StartRefresh(time.Millisecond*10, "./trigger.sh", "./trigger.sh")
		time.Sleep(time.Millisecond * 10)
		fmt.Println(callScript(`
			docker exec docker-discover docker run -d --label PD_HOST=80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST=80 --name ds-srv-v1.0.1 --restart always -P nginx
		`))
		fmt.Println(callScript(`
			docker exec docker-discover docker start ds-srv-v1.0.0
		`))
		time.Sleep(time.Millisecond * 10)
		fmt.Println(callScript(`
			docker exec docker-discover docker stop ds-srv-v1.0.0
		`))
		time.Sleep(time.Millisecond * 10)
		discover.StopRefresh()
	}
	{ //control
		fmt.Println(callScript(`
			docker exec docker-discover docker rm -f ds-srv-v1.0.0
			docker exec docker-discover docker rm -f ds-srv-v1.0.1
			docker exec docker-discover docker rm -f ds-srv-v1.0.2
			docker exec docker-discover docker run -d --name ds-abc-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST=80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
		`))
		discover.Refresh()
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/ps", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if !strings.Contains(res.Body.String(), "ds-srv-v1.0.0") || !strings.Contains(res.Body.String(), "ds-abc-v1.0.0") {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/stop", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if res.Body.String() != "ok" {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/start", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if res.Body.String() != "ok" {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/restart", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if res.Body.String() != "ok" {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/restart?id=ds-abc-v1.0.0", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if res.Body.String() != "ok" {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/psx", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("ds", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if !strings.Contains(res.Body.String(), "404") {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/ps", nil)
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if !strings.Contains(res.Body.String(), "unauthorized") {
				t.Error(res.Body.String())
				return
			}
		}
		{
			req := httptest.NewRequest("GET", "http://v100.ds.test.loc/_s/docker/ps", nil)
			req.Header.Set("Authorization", "Basic "+basicAuth("dsx", "abc"))
			res := httptest.NewRecorder()
			discover.ServeHTTP(res, req)
			if !strings.Contains(res.Body.String(), "invalid") {
				t.Error(res.Body.String())
				return
			}
		}
	}
	{ //log
		fmt.Println(callScript(`
			docker exec docker-discover docker start ds-srv-v1.0.0
		`))
		ts := httptest.NewServer(discover)
		dialer := xnet.NewWebsocketDialer()
		dialer.Dialer = xnet.RawDialerF(func(network, address string) (net.Conn, error) {
			return net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
		})
		remote := "ws://ds:abc@v100.ds.test.loc/_s/docker/logs"
		conn, err := dialer.Dial(remote)
		if err != nil {
			t.Error(err)
			return
		}
		io.Copy(ioutil.Discard, conn)
		conn.Close()
	}
}

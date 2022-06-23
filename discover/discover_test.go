package discover

import (
	"encoding/base64"
	"fmt"
	"html/template"
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

	"github.com/codingeasygo/util/xhttp"
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
			docker exec docker-discover docker run -d --label PD_HOST_WWW=*/:80 --label PD_TCP_WWW=:8080/:80 --label PD_UDP_WWW=:8080/:80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST_WWW=:80 --label PD_TCP_WWW=:8081/:80 --label PD_UDP_WWW=:8081/:80 --name ds-srv-v1.0.1 --restart always -P nginx
		`))
	}
	pwd, _ := os.Getwd()
	dockerHost := callScript(`docker inspect --format="{{.NetworkSettings.IPAddress}}" docker-discover`)
	dockerCert := filepath.Join(pwd, "../test/certs/client")
	dockerAddr := fmt.Sprintf("tcp://%v:2376", dockerHost)
	hostSuff := ".test.loc"
	discover := NewDiscover()
	discover.HostSuff = hostSuff
	discover.HostProto = "http:"
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
		if err != nil || len(all) != 6 || len(added) != 6 || len(removed) != 0 {
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
		req10 := httptest.NewRequest("GET", "http://xx.v100.ds.test.loc/", nil)
		res10 := httptest.NewRecorder()
		discover.ServeHTTP(res10, req10)
		if !strings.Contains(res10.Body.String(), "nginx") {
			t.Error(res10.Body.String())
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
		fmt.Println(res3.Body.String())
		res4, err := xhttp.GetText("http://127.0.0.1:8080")
		if err != nil || !strings.Contains(res4, "nginx") {
			t.Errorf("%v,%v", err, res4)
			return
		}
		reqPreview1 := httptest.NewRequest("GET", "http://pdsrv/", nil)
		resPreview1 := httptest.NewRecorder()
		discover.ServeHTTP(resPreview1, reqPreview1)
		if !strings.Contains(resPreview1.Body.String(), "Having") {
			t.Error(resPreview1.Body.String())
			return
		}
		reqPreview2 := httptest.NewRequest("GET", "http://pdsrv/", nil)
		resPreview2 := httptest.NewRecorder()
		discover.Preview, _ = template.New("test").Parse(`
		template
		`)
		discover.ServeHTTP(resPreview2, reqPreview2)
		if !strings.Contains(resPreview2.Body.String(), "template") {
			t.Error(resPreview2.Body.String())
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
		if err != nil || len(all) != 3 || len(added) != 0 || len(updated) != 0 || len(removed) != 3 {
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
		fmt.Println("--> test container update")
		discover.DockerFinder = "./finder.sh"
		discover.DockerCert = ""
		discover.DockerAddr = ""
		discover.DockerHost = ""
		fmt.Println(callScript(`
			docker exec docker-discover docker stop ds-srv-v1.0.1
			docker exec docker-discover docker start ds-srv-v1.0.1
		`))
		time.Sleep(100 * time.Millisecond)
		all, added, updated, removed, err := discover.Refresh()
		if err != nil || len(all) != 3 || len(added) != 0 || len(updated) != 3 || len(removed) != 0 {
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
	{ //prefix
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
			docker exec docker-discover docker run -d --label PD_HOST_WWW=/:80 --label PD_HOST_A0=a0/:80 --label PD_HOST_A1=a1/:80 --name ds-srv-v1.0.2 --restart always -P nginx
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
			docker exec docker-discover docker run -d --label PD_HOST_WWW=/:80 --label PD_HOST_XX=/:8080 --label PD_TCP_XY=:0/:8080 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST_WWW=/:80 --label PD_HOST_XX=/:8080 --label PD_TCP_XY=:0/:8080 --label PD_TCP_ERR=:0 --name ds-srv-v1.0.1 --restart always -P nginx
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
			docker exec docker-discover docker run -d --label PD_HOST_WWW=/:80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
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
	{ //clear
		fmt.Println(callScript(`
			docker exec docker-discover docker rm -f ds-srv-v1.0.0
			docker exec docker-discover docker rm -f ds-srv-v1.0.1
			docker exec docker-discover docker rm -f ds-srv-v1.0.2
		`))
		time.Sleep(time.Millisecond * 10)
		fmt.Println(callScript(`
			docker exec docker-discover docker run -d --label PD_HOST_WWW=*/:80 --label PD_TCP_WWW=:8080/:80 --label PD_UDP_WWW=:8080/:80 --label PD_SERVICE_TOKEN=abc --name ds-srv-v1.0.0 --restart always -P nginx
			docker exec docker-discover docker run -d --label PD_HOST_WWW=:80 --label PD_TCP_WWW=:8081/:80 --label PD_UDP_WWW=:8081/:80 --name ds-srv-v1.0.1 --restart always -P nginx
		`))
		time.Sleep(2 * time.Second)
		discover.DockerClearDelay = time.Second
		discover.DockerClearExc = []string{"ds-srv-v1.0.1"}
		_, err := discover.Clear()
		if err != nil {
			t.Error(err)
			return
		}
		discover.DockerPruneDelay = time.Second
		discover.DockerPruneExc = []string{"network"}
		err = discover.Prune()
		if err != nil {
			t.Error(err)
			return
		}
	}
}

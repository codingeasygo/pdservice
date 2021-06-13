package discover

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestDiscover(t *testing.T) {
	pwd, _ := os.Getwd()
	dockerHost := callScript(`docker inspect --format="{{.NetworkSettings.IPAddress}}" docker-discover`)
	dockerCert := filepath.Join(pwd, "../test/certs/client")
	dockerAddr := fmt.Sprintf("tcp://%v:2376", dockerHost)
	hostSuff := ".test.loc"
	discover := NewDiscover()
	discover.HostSuff = hostSuff
	{
		discover.DockerFinder = ""
		discover.DockerCert = dockerCert
		discover.DockerAddr = dockerAddr
		discover.DockerHost = dockerHost
		fmt.Println(callScript(`
			docker exec docker-discover docker start ds-srv-v1.0.0
			docker exec docker-discover docker start ds-srv-v1.0.1
		`))
		all, added, removed, err := discover.Refresh()
		if err != nil || len(all) != 2 || len(added) != 2 || len(removed) != 0 {
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
	}
	{
		discover.DockerFinder = "./finder.sh"
		discover.DockerCert = ""
		discover.DockerAddr = ""
		discover.DockerHost = ""
		fmt.Println(callScript(`
			docker exec docker-discover docker stop ds-srv-v1.0.0
		`))
		all, added, removed, err := discover.Refresh()
		if err != nil || len(all) != 1 || len(added) != 0 || len(removed) != 1 {
			fmt.Printf("all->%v\nadded->%v\nremoved-->%v\n\n", all, added, removed)
			t.Error(err)
			return
		}
		req1 := httptest.NewRequest("GET", "http://v100.ds.test.loc/", nil)
		res1 := httptest.NewRecorder()
		discover.ServeHTTP(res1, req1)
		if !strings.Contains(res1.Body.String(), "404") {
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
		discover.StartRefresh(time.Millisecond*10, "./trigger.sh", "./trigger.sh")
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
}

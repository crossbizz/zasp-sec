//go:build darwin || linux

package sandboxcutover

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestObservationWatcherFailureStopsUnreapedGroup(t *testing.T) {
	root := t.TempDir()
	ready, stop := filepath.Join(root, "ready"), filepath.Join(root, "stop")
	child := `const fs=require('fs'),net=require('net');process.on('SIGTERM',()=>{});const ready=` + strconv.Quote(ready) + `;net.createServer(c=>c.end()).listen(0,'127.0.0.1',function(){const tmp=ready+'.'+process.pid;fs.writeFileSync(tmp,String(this.address().port),{flag:'wx'});fs.renameSync(tmp,ready)});setInterval(()=>{if(fs.existsSync(` + strconv.Quote(stop) + `))process.exit(0)},10);setTimeout(()=>process.exit(0),10000)`
	leader := `const fs=require('fs');require('child_process').spawn(process.execPath,['-e',` + strconv.Quote(child) + `],{stdio:'ignore'});setInterval(()=>{if(fs.existsSync(` + strconv.Quote(stop) + `))process.exit(0)},10);setTimeout(()=>process.exit(0),10000)`
	var address string
	t.Cleanup(func() {
		_ = os.WriteFile(stop, nil, 0600)
		for until := time.Now().Add(2 * time.Second); address != "" && time.Now().Before(until); {
			connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err != nil {
				return
			}
			connection.Close()
			time.Sleep(10 * time.Millisecond)
		}
	})
	watcher := func(int) error {
		for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
			if body, err := os.ReadFile(ready); err == nil {
				if port, err := strconv.Atoi(string(body)); err == nil && port >= 1 && port <= 65535 {
					address = "127.0.0.1:" + strconv.Itoa(port)
					return errors.New("injected kernel watcher failure after live group startup")
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		return errors.New("fixture did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	body, err := runObservationProcessWithWatcher(ctx, exec.Command(observationNode(t), "-e", leader), watcher)
	if err == nil || len(body) != 0 || time.Since(started) > 4*time.Second {
		t.Fatal("watcher failure did not refuse within cleanup bound", err)
	}
	if address == "" {
		t.Fatal("watcher never observed live descendant")
	}
	if connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("watcher failure left descendant listener alive")
	}
}

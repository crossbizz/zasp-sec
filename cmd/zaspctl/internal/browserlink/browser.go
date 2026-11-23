// Package browserlink opens a first-party link at an explicitly selected HTTPS origin.
package browserlink

import (
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func Origin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
	}
	host := strings.ToLower(u.Host)
	host = strings.TrimSuffix(host, ":443")
	return "https://" + host, true
}

func Open(link string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("/usr/bin/open", link)
	case "linux":
		cmd = exec.Command("/usr/bin/xdg-open", link)
	case "windows":
		// Explorer receives the complete URL as an argument without a command shell.
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			return
		}
		cmd = exec.Command(systemRoot+`\explorer.exe`, link)
	default:
		return
	}
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}

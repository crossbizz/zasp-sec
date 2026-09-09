package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("fixture mode required")
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(os.Getenv("PROOF_NONCE")) {
		return errors.New("fixture nonce required")
	}
	switch os.Args[1] {
	case "serve":
		return serve()
	case "control":
		if err := expectNonce(os.Getenv("PROOF_TARGET") + ":443"); err != nil {
			return err
		}
		fmt.Println(`{"reachable":true}`)
		return nil
	case "probe":
		return probe()
	case "enforce":
		return enforce()
	default:
		return errors.New("unknown fixture mode")
	}
}

var client = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func expectNonce(address string) error {
	response, err := client.Get("http://" + address + "/proof")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 129))
	if err != nil || response.StatusCode != 200 || string(body) != os.Getenv("PROOF_NONCE") {
		return errors.New("control endpoint nonce mismatch")
	}
	return nil
}

// These are controlled transport endpoints, not substitutes for the production
// TLS/token proxy. That separate authorization boundary has its own acceptance.
func serve() error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/proof" {
			http.NotFound(w, r)
			return
		}
		if target := os.Getenv("PROOF_FORWARD"); target != "" {
			if err := expectNonce(target + ":443"); err != nil {
				http.Error(w, "upstream unavailable", 502)
				return
			}
		}
		fmt.Fprint(w, os.Getenv("PROOF_NONCE"))
	})
	failures := make(chan error, 3)
	for _, port := range []string{"443", "8443", "8080"} {
		listener, err := net.Listen("tcp4", ":"+port)
		if err != nil {
			return err
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
		go func() { failures <- server.Serve(listener) }()
	}
	return <-failures
}

func probe() error {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || os.Getuid() != 65532 || !strings.Contains(string(status), "CapEff:\t0000000000000000") {
		return errors.New("probe must have no capabilities and non-root identity")
	}
	if err := expectNonce(os.Getenv("PROOF_PROXY") + ":8443"); err != nil {
		return fmt.Errorf("proxy positive control: %w", err)
	}
	if err := expectNonce(os.Getenv("PROOF_INFRA") + ":443"); err != nil {
		return fmt.Errorf("infrastructure positive control: %w", err)
	}
	for _, address := range []string{os.Getenv("PROOF_TARGET") + ":443", os.Getenv("PROOF_PROXY") + ":8080"} {
		connection, err := net.DialTimeout("tcp4", address, 1500*time.Millisecond)
		if connection != nil {
			connection.Close()
			return errors.New("undeclared direct connection succeeded")
		}
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			return fmt.Errorf("not a packet-drop denial: %w", err)
		}
	}
	fmt.Println(`{"proxy_allowed":true,"infra_allowed":true,"direct_denied":true,"wrong_port_denied":true,"uid":65532,"capabilities":0}`)
	return nil
}

func enforce() error {
	source, err := os.ReadFile("/contract.json")
	if err != nil {
		return err
	}
	rules, err := readContract(source)
	if err != nil {
		return err
	}
	addresses := map[string]net.IP{}
	for _, name := range []string{"PROOF_PROXY", "PROOF_INFRA", "PROOF_TARGET"} {
		address := net.ParseIP(os.Getenv(name)).To4()
		if address == nil || !address.IsPrivate() {
			return errors.New("private owned endpoint IP required")
		}
		addresses[name] = address
	}
	if addresses["PROOF_TARGET"].Equal(addresses["PROOF_PROXY"]) || addresses["PROOF_TARGET"].Equal(addresses["PROOF_INFRA"]) || addresses["PROOF_PROXY"].Equal(addresses["PROOF_INFRA"]) {
		return errors.New("distinct endpoint classes required")
	}
	connection, err := nftables.New()
	if err != nil {
		return err
	}
	// INet covers both IP families. Only explicit IPv4 endpoint rules accept.
	table := connection.AddTable(&nftables.Table{Name: "zasp_owned_fixture", Family: nftables.TableFamilyINet})
	policy := nftables.ChainPolicyDrop
	chain := connection.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	for name, rule := range rules {
		ip := addresses["PROOF_INFRA"]
		if name == "proxy" {
			ip = addresses["PROOF_PROXY"]
		}
		protocol := byte(unix.IPPROTO_TCP)
		if rule.Protocol == "udp" {
			protocol = unix.IPPROTO_UDP
		}
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, rule.Port)
		connection.AddRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte(name), Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
			&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept},
		}})
	}
	connection.AddRule(&nftables.Rule{Table: table, Chain: chain, UserData: []byte("denied"), Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
	if err := connection.Flush(); err != nil {
		return fmt.Errorf("install kernel policy: %w", err)
	}
	defer func() { connection.DelTable(table); _ = connection.Flush() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proof", "probe")
	command.Env = []string{"PROOF_NONCE=" + os.Getenv("PROOF_NONCE"), "PROOF_PROXY=" + os.Getenv("PROOF_PROXY"), "PROOF_INFRA=" + os.Getenv("PROOF_INFRA"), "PROOF_TARGET=" + os.Getenv("PROOF_TARGET")}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532, Groups: []uint32{}}}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unprivileged probe failed: %w: %s", err, output)
	}
	observed, err := connection.GetRules(table, chain)
	if err != nil {
		return err
	}
	var packets uint64
	for _, rule := range observed {
		if string(rule.UserData) == "denied" {
			for _, expression := range rule.Exprs {
				if counter, ok := expression.(*expr.Counter); ok {
					packets += counter.Packets
				}
			}
		}
	}
	if packets == 0 {
		return errors.New("no kernel-observed denied packets")
	}
	var result map[string]any
	if json.Unmarshal(output, &result) != nil {
		return errors.New("malformed probe receipt")
	}
	result["kernel_dropped_packets"] = strconv.FormatUint(packets, 10)
	result["proof_boundary"] = "owned Linux network namespace; not live AWS security-group attachment"
	return json.NewEncoder(os.Stdout).Encode(result)
}

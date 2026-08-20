package kubernetesdiscovery

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type pinnedCollectionResolverStub struct {
	addresses []net.IPAddr
	err       error
	calls     int
}

func (stub *pinnedCollectionResolverStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	stub.calls++
	return append([]net.IPAddr(nil), stub.addresses...), stub.err
}

type pinnedCollectionDialerStub struct {
	network, address string
	calls            int
	err              error
}

func (stub *pinnedCollectionDialerStub) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	stub.calls++
	stub.network, stub.address = network, address
	return nil, stub.err
}

func TestPinnedKubernetesCollectionDialRequiresAllDNSAnswersAllowedAndPinsIP(t *testing.T) {
	resolver := &pinnedCollectionResolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}, {IP: net.ParseIP("2001:db8::8")}}}
	dialer := &pinnedCollectionDialerStub{err: errors.New("dial stopped")}
	api, err := newPinnedKubernetesCollectionAPI(PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Timeout: time.Second}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	transport := api.client.Transport.(*http.Transport)
	_, err = transport.DialContext(context.Background(), "tcp", "cluster.example.test:443")
	if err == nil || dialer.calls != 1 || dialer.address != "203.0.113.8:443" || resolver.calls != 1 || transport.Proxy != nil || transport.TLSClientConfig.ServerName != "cluster.example.test" {
		t.Fatalf("pinning not exact: resolver=%#v dialer=%#v transport=%#v err=%v", resolver, dialer, transport, err)
	}

	resolver.addresses = append(resolver.addresses, net.IPAddr{IP: net.ParseIP("10.0.0.8")})
	dialer.calls = 0
	if _, err := transport.DialContext(context.Background(), "tcp", "cluster.example.test:443"); err == nil || dialer.calls != 0 {
		t.Fatal("mixed allowed/private DNS answer reached dialer")
	}
}

func TestPinnedKubernetesCollectionRejectsAuthorityDrift(t *testing.T) {
	valid := PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second}
	tests := []func(*PinnedCollectionAPIConfig){
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = nil },
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = []string{"203.0.113.1/24"} },
		func(config *PinnedCollectionAPIConfig) { config.AllowedCIDRs = []string{"0.0.0.0/0"} },
		func(config *PinnedCollectionAPIConfig) {
			config.CABundlePEM = append(config.CABundlePEM, []byte("trailing")...)
		},
		func(config *PinnedCollectionAPIConfig) { config.Endpoint = "https://127.0.0.1" },
	}
	for index, mutate := range tests {
		config := valid
		config.CABundlePEM = append([]byte(nil), valid.CABundlePEM...)
		config.AllowedCIDRs = append([]string(nil), valid.AllowedCIDRs...)
		mutate(&config)
		if _, err := newPinnedKubernetesCollectionAPI(config, &pinnedCollectionResolverStub{}, &pinnedCollectionDialerStub{}); err == nil {
			t.Fatalf("hostile config %d accepted", index)
		}
	}
}

func TestPinnedKubernetesCollectionRejectsWrongDialHostAndUnboundedDNS(t *testing.T) {
	resolver := &pinnedCollectionResolverStub{addresses: make([]net.IPAddr, 17)}
	for index := range resolver.addresses {
		resolver.addresses[index] = net.IPAddr{IP: net.ParseIP("203.0.113." + strconv.Itoa(index+1))}
	}
	dialer := &pinnedCollectionDialerStub{}
	api, err := newPinnedKubernetesCollectionAPI(PinnedCollectionAPIConfig{Endpoint: "https://cluster.example.test", CABundlePEM: []byte(testPinnedCertificatePEM), AllowedCIDRs: []string{"203.0.113.0/24"}, Timeout: time.Second}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	transport := api.client.Transport.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "other.example.test:443"); err == nil || dialer.calls != 0 {
		t.Fatal("foreign host reached dialer")
	}
	_, dialErr := transport.DialContext(context.Background(), "tcp", "cluster.example.test:443")
	if dialErr == nil || dialer.calls != 0 {
		t.Fatal("unbounded DNS set reached dialer")
	}
	if strings.Contains(dialErr.Error(), "cluster.example.test") {
		t.Fatal("stable error exposed endpoint")
	}
}

const testPinnedCertificatePEM = `-----BEGIN CERTIFICATE-----
MIICvjCCAaYCCQCa7cxZ6Y3MiTANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZ6
YXNwLWRpc2NvdmVyeS10ZXN0LWNhMB4XDTI2MDgyMDA5MTQxNloXDTM2MDgxNzA5
MTQxNlowITEfMB0GA1UEAwwWemFzcC1kaXNjb3ZlcnktdGVzdC1jYTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANh6kp693Js5s/ywepHGGfE7RTk1pt1w
PkPnqrnKa4t1WXrvITg1qedB3L3RvvXBPXYGV+8VOba4rmA7utEO0sHcbzfINGYq
wkdpOtuh+RwLmCNV23ON+snR9NbKtqeFB1Res/AkWvynIFotV5dw8Hx2AgMzBjy8
Hcffg28rN0C4GwzevV/kZ/rJFKsaK2NQR13khiTdVsbxoVPyI059T0iJ1/C4HthH
hL30/vtPdCQrAWmUri/+v/mCVbNaObBSQSx+1IlWWyXcngJyIaV5UF7r0gJtmPxq
dy9QJDcg129UYtEI1nrDFOQarinotqi3Piul6KEEWpCfV8XPAejRPlkCAwEAATAN
BgkqhkiG9w0BAQsFAAOCAQEAMH7DRwGWSGQsgYZ60GHATgxtjMgyPdj25gdgAs4l
mpWnq1ZPjbip6qTKsieLLTwnbkTI2wH4TPq70ap9yopJVc0cmytAWzRT2IaECDp7
ZPrYLLzuZ9aco0pdECZZObO036RLWnPGWTr8uUnLiS6SCJKDYSBoltxHwYOxlGlC
MOcVZWwReBWmZPdqvXbWVJbcf1XnCYnaMOh57My+6HO5n/HTRFR6eGTx6gK9IL25
c+ycq4+Zi7euxAKVlGLmEVTLX9y09AQq9YOk8A8SWuYhYV+CcOduXy9k15O0OJIJ
bVTUV5LTcltIKutavvUDzuCeBB13DHmiz84JpOusjUjBQQ==
-----END CERTIFICATE-----
`

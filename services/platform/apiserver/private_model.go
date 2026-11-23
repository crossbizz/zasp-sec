package apiserver

import (
	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func configuredPrivateModel(p aigateway.Purpose, prefix string) *analystChat {
	f, err := os.Open(os.Getenv(prefix + "TOKEN_FILE"))
	if err != nil {
		return nil
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0022 != 0 || stat.Size() > 8193 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, 8194))
	if err != nil || len(data) > 8193 {
		return nil
	}
	ip, err := netip.ParseAddr(os.Getenv(prefix + "VPCE_IP"))
	if err != nil {
		return nil
	}
	cost, err := strconv.ParseInt(os.Getenv(prefix+"MAX_NANO_CREDITS"), 10, 64)
	if err != nil {
		return nil
	}
	driver, b, err := aigateway.NewBedrockForPurpose(p, os.Getenv(prefix+"VPCE_HOST"), ip, os.Getenv(prefix+"MODEL"), os.Getenv(prefix+"CREDENTIAL_REFERENCE"), strings.TrimSuffix(string(data), "\n"), cost)
	if err != nil {
		return nil
	}
	return &analystChat{driver, b}
}

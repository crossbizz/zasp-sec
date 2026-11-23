package share

import (
	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/privatewin"
	"os"
)

func openCIKey(path string) (*os.File, error) {
	file, err := privatewin.Open(path, false)
	if err != nil {
		return nil, errReport
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 4096 {
		file.Close()
		return nil, errReport
	}
	return file, nil
}

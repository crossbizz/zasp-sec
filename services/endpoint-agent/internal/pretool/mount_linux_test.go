package pretool

import "testing"

func TestLocalMountClassificationAvoidsRemoteMetadata(t *testing.T) {
	const mounts = "3 1 1:0 / / rw - ext4 /dev/test rw\n4 3 2:0 / /data/remote rw - nfs synthetic rw\n5 3 3:0 / /data/auto rw - autofs fixture rw\n"
	for _, c := range []struct {
		path  string
		local bool
	}{{"/data/work", true}, {"/data/remote/guide", false}, {"/data/remote2/guide", true}, {"/data/auto", false}} {
		if got := localMountsCover(mounts, c.path); got != c.local {
			t.Errorf("classification %s=%t", c.path, got)
		}
	}
	if localMountsCover("truncated", "/data/guide") {
		t.Error("malformed table accepted")
	}
}

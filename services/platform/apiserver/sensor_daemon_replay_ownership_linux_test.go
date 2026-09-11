package apiserver

import (
	"os"
	"testing"
)

type daemonReplayCleanupReportFixture struct {
	failed bool
	errors int
}

func (*daemonReplayCleanupReportFixture) Helper()             {}
func (report *daemonReplayCleanupReportFixture) Failed() bool { return report.failed }
func (*daemonReplayCleanupReportFixture) Log(...any)          {}
func (report *daemonReplayCleanupReportFixture) Error(...any) { report.failed = true; report.errors++ }

func TestSensorDaemonReplayOwnershipCleanup(t *testing.T) {
	for _, condition := range []string{"joined", "failed-join", "replaced-root"} {
		t.Run(condition, func(t *testing.T) {
			ownership := &daemonReplayOwnership{}
			root := ownership.root(t)
			// This test owns both names and has no child process using them.
			defer os.RemoveAll(root)
			report := &daemonReplayCleanupReportFixture{failed: condition == "failed-join"}
			if condition == "replaced-root" {
				held := root + ".held"
				if err := os.Rename(root, held); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(held)
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ownership.cleanup(report)
			_, err := os.Lstat(root)
			if condition == "joined" {
				if !os.IsNotExist(err) || report.errors != 0 {
					t.Fatal("joined cleanup didn't remove its exact root", err)
				}
			} else if err != nil {
				t.Fatal("failed join or changed root didn't preserve state", err)
			}
			if condition == "replaced-root" && report.errors != 1 {
				t.Fatal("changed root wasn't reported")
			}
		})
	}
}

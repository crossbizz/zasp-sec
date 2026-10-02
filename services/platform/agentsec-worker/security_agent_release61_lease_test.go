package main

import (
	"reflect"
	"testing"
	"time"
)

func TestRelease61DeploymentLeaseBounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		duration time.Duration
		seconds  int
		valid    bool
	}{
		{"default", 0, 300, true}, {"minimum", 30 * time.Second, 30, true},
		{"maximum", 300 * time.Second, 300, true}, {"negative", -time.Second, 0, false},
		{"too_short", 30*time.Second - time.Nanosecond, 0, false},
		{"too_long", 300*time.Second + time.Nanosecond, 0, false},
		{"fractional", 31*time.Second + time.Nanosecond, 0, false},
		{"overflow", time.Duration(1<<63 - 1), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &securityAgentRelease61Runtime{}
			config, ok := any(r).(interface{ deploymentLeaseSeconds() (int, error) })
			field := reflect.ValueOf(r).Elem().FieldByName("DeploymentLeaseDuration")
			if !ok || !field.IsValid() || !field.CanSet() {
				t.Fatal("bounded dormant deployment lease configuration absent")
			}
			field.SetInt(int64(tc.duration))
			seconds, err := config.deploymentLeaseSeconds()
			if (err == nil) != tc.valid || seconds != tc.seconds {
				t.Fatal("deployment lease not preserved or bounded", seconds, err)
			}
		})
	}
}

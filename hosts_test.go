package main

import (
	"reflect"
	"runtime"
	"testing"
)

func TestPingArgs(t *testing.T) {
	var want []string
	switch runtime.GOOS {
	case "linux":
		want = []string{"-c", "1", "-W", "1", "192.0.2.1"}
	case "windows":
		want = []string{"-n", "1", "-w", "1000", "192.0.2.1"}
	default:
		t.Skip("ping arguments are defined for Linux and Windows")
	}

	if got := pingArgs("192.0.2.1"); !reflect.DeepEqual(got, want) {
		t.Fatalf("pingArgs() = %v, want %v", got, want)
	}
}

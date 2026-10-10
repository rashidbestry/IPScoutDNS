package main

import (
	"reflect"
	"testing"
)

func TestPingExplicitInterface(t *testing.T) {
	for _, selector := range []string{"eth0", "192.0.2.10", " eth0 "} {
		wantSelector := selector
		if selector == " eth0 " {
			wantSelector = "eth0"
		}
		want := []string{"-c", "1", "-W", "1", "-I", wantSelector, "192.0.2.1"}
		got, err := pingArgs("192.0.2.1", selector)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("pingArgs(%q) = %v, %v; want %v, nil", selector, got, err, want)
		}
	}
}

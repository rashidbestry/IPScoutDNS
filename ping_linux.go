package main

import "strings"

func pingArgs(ip string, interfaceSelector string) ([]string, error) {
	args := []string{"-c", "1", "-W", "1"}
	selector := strings.TrimSpace(interfaceSelector)
	if selector != "" && !strings.EqualFold(selector, "default") {
		args = append(args, "-I", selector)
	}
	return append(args, ip), nil
}

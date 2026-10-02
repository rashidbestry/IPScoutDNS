package main

func pingArgs(ip string) []string {
	return []string{"-n", "1", "-w", "1000", ip}
}

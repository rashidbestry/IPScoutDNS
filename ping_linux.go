package main

func pingArgs(ip string) []string {
	return []string{"-c", "1", "-W", "1", ip}
}

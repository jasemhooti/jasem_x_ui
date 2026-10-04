//go:build !linux

package singbox

func killStraySingboxProcesses(_ string) int { return 0 }

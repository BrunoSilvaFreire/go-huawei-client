package eg8145v5

import "strings"

type UserDevice struct {
	Domain                  string
	IpAddr                  string
	MacAddr                 string
	Port                    string
	PortID                  string
	DevStatus               string
	IpType                  string
	Time                    string
	HostName                string
	IPv4Enabled             string
	IPv6Enabled             string
	DeviceType              string
	UserDevAlias            string
	UserSpecifiedDeviceType string
	LeaseTimeRemaining      string
}

type StaticDnsHost struct {
	DomainName string
	IPAddress  string
}

func (d *UserDevice) Online() bool {
	return strings.EqualFold(d.DevStatus, "online")
}

var (
	ResourceUsageFuncScript = `
	function resourceUsage() {
		return {
			Memory: Number(memUsed.slice(0, -1)),
			CPU: Number(cpuUsed.slice(0, -1)),
		}
	}
	`
	ResourceUsageFuncName = "resourceUsage"
)

type ResourceUsage struct {
	Memory int // Memory usage in percent (0-100)
	CPU    int // CPU usage in percent (0-100)
}

package global

type Output struct {
	IP       string
	Hostname string
	PortData []PortData
}

type PortData struct {
	Port     int
	Protocol string
	Service  string
	Product  string
	Version  string
}

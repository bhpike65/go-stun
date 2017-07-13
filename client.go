package main

import (
	"flag"
	"fmt"
	"github.com/bhpike65/go-stun/nat"
	"net"
	"os"
)

var server = flag.String("server", "stun.l.google.com:19302", "STUN server to query")
var altServer = flag.String("alt-server", "", "alternative STUN server to query")
var local = flag.String("local", "", "local ip:port to use")

func main() {
	flag.Parse()

	if *local == "" {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			fmt.Println("get interface addrs error: ", err.Error())
			os.Exit(-1)
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					*local = ipnet.IP.String() + ":0"
				}
			}
		}
	}

	res, err := nat.Discovery(*local, *server, *altServer)
	if err != nil {
		fmt.Println("nat discovery error: ", err.Error())
		os.Exit(-1)
	}

	fmt.Printf("nat discovery result:\n%s", res)
	return
}

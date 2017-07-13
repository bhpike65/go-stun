# go-stun

Go implementation of STUN

# stun

## stun client

```go
   package main

   import (
   	"github.com/bhpike65/go-stun/stun"
   	"fmt"
   	"os"
   )

   func main() {
        req := stun.NewBindRequest(nil)
        req.SetChangeIP(true)
        req.SetChangePort(true)
        resp, localAddr, err := req.Request("192.168.1.3"", "stun.l.google.com:19302")
        if err != nil {
            fmt.Println("Failed to build STUN PP request:", err)
            os.Exit(1)
        }
        fmt.Println("mapping address: ", resp.Addr.String())
   }
```

## stun server

```go
   package main

   import (
   	"github.com/bhpike65/go-stun/stun"
   	"fmt"
   )

   func main() {
        addr, _ := net.ResolveUDPAddr("udp", "1.1.1.1:3478")
        conn, _ := net.ListenUDP("udp", addr)
        buf := make([]byte, 1500)
        for {
            n, remote, err := conn.ReadFromUDP(buf)

            var req stun.StunMessageReq
            if err = req.Unmarshal(buf[:n]); err != nil {
                continue
            }
            if err = req.RespondTo(conn, remote, other); err != nil {
                continue
            }
        }
   }
```

# NAT Behaviour Discovery

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"github.com/bhpike65/go-stun/nat"
	"net"
)

func main() {
	res, err := nat.Discovery("192.168.1.1:0", "stun.l.google.com:19302", "")
	if err != nil {
		fmt.Println("nat discovery error: ", err.Error())
		os.Exit(-1)
	}

	fmt.Printf("nat discovery result:\n%s", res)
	return
}
```

it will output:
```text
localAddress:192.168.1.3:56010, mappingAddress:1.1.1.1:15168
NAT mapping type: Endpoint-Independent Mapping NAT
NAT filtering type: Endpoint-Independent Filtering NAT
NAT Hairpinning Support: YES
```

# Example Usage

## server
```sh
go run ./server.go -primary-addr 1.1.1.1 -primary-port 3478  -alt-address 2.2.2.2 -alt-port 3479
```
or you can let the program auto select the public IP from the interface

```sh
go run ./server.go -public
```

## slave server
if you don't have two public IP address in one machine, instead, you can use two machine and specify one as slave server.

1. start slave server
```sh
go run server.go -slave -slaveserver 1.1.1.1:12345 -primary-addr 2.2.2.2 -primary-port 3478 -alt-port 3479
```
then it will start a tcp server listen on 1.1.1.1:12345, and waits request from master server.
you should add iptables rules to filter the packet which doesn't come from master server.


2. start master server
```sh
go run server.go -slaveserver 1.1.1.1:12345 -primary-addr 1.1.1.1 -primary-port 3478  -alt-port 3479
```
if master don't have alt-addr public IP,  and the ChangeIP Bit in Bonding Request is set, then it will let slaveserver to reply to it.
slaveserver and master server should have the same primary-port and alt-port

## client
```sh
go run client.go -server 1.1.1.1:3478 -alt-server 2.2.2.2:3479
```
and get the NAT behaviour test result:
```text
localAddress:192.168.1.3:49191, mappingAddress:3.3.3.3:37408
Address and Port-Dependent Mapping NAT
Endpoint-Independent Filtering NAT
NAT Hairpinning Support: YES
```

# Spec
- [RFC 4787: NAT](https://tools.ietf.org/html/rfc787)
- [RFC 5389: STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5780: NAT Behaviour Discovery](https://tools.ietf.org/html/rfc5780)

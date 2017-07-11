package main

import (
	"flag"
	"net"
	"os"
	"bufio"
	"fmt"
	"go-stun/stun"
	"log"
	"io"
	"strings"
	"encoding/hex"
)

const (
	typePP        = iota // primaryAddr:primaryPort
	typePA               // primaryAddr:alterAddr
	typeAP               // alterAddr:primaryPort
	typeAA        		 // alterAddr:alterAddr
	typeMax
)

var roleSet [typeMax]*net.UDPConn

var logger              *log.Logger

// ./stunserver --primaryAddr 1.1.1.1 --alternativeAddr 2.2.2.2 --primaryPort 3478 --alternativePort 3479
// ./stunserver --slaveserver 2.2.2.2:12345 --primaryAddr 1.1.1.1 --primaryPort 3478 --alternativePort 3479
// ./stunserver --slave --slaveserver 2.2.2.2:12345 --primaryPort 3478 --alternativePort 3479

var primaryAddr = flag.String("primary-addr", "", "STUN server primary address")
var alterAddr = flag.String("alt-addr", "", "STUN server alternative address")
var primaryPort = flag.Int("primary-port", 3478, "primary port")
var alterPort = flag.Int("alt-port", 3479, "alternative port")
var slaveServer = flag.String("slaveserver", "", "slave STUN server which has alternative Ip")

var isSlave = flag.Bool("slave", false, "this is a slave stun server")
var public = flag.Bool("public", true, "primaryAddr and alternativeAddr must be public ip address")

var slaveChan chan *string


var lanNets = []*net.IPNet{
	{net.IPv4(10, 0, 0, 0), net.CIDRMask(8, 32)},
	{net.IPv4(172, 16, 0, 0), net.CIDRMask(12, 32)},
	{net.IPv4(192, 168, 0, 0), net.CIDRMask(16, 32)},
	{net.ParseIP("fc00"), net.CIDRMask(7, 128)},
}

func main() {
	flag.Parse()

	logFile, err  := os.OpenFile("./slave.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("failed to create slave.log: ", err.Error())
		os.Exit(-1)
	}
	logger = log.New(logFile,"",log.Llongfile | log.LstdFlags)

	if *primaryAddr == "" || *alterAddr == "" {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			logger.Fatal("get interface addrs error: ", err.Error())
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if *public {
					for _, lan := range lanNets {
						if ipnet.IP.To4() != nil && !lan.Contains(ipnet.IP) {
							if *primaryAddr == "" {
								*primaryAddr = ipnet.IP.String()
							} else if *alterAddr == "" && *primaryAddr !=  ipnet.IP.String() {
								*alterAddr = ipnet.IP.String()
							} else {
								break
							}
						}
					}
				} else {
					if ipnet.IP.To4() != nil {
						if *primaryAddr == "" {
							*primaryAddr = ipnet.IP.String()
						} else if *alterAddr == "" {
							*alterAddr = ipnet.IP.String()
						} else {
							break
						}
					}
				}
			}
		}
	}

	roleSet[typePP], err = net.ListenUDP("udp", &net.UDPAddr{IP:net.ParseIP(*primaryAddr), Port:*primaryPort})
	if err != nil {
		logger.Fatal("listen on PP failed")
	}
	roleSet[typePA], err = net.ListenUDP("udp", &net.UDPAddr{IP:net.ParseIP(*primaryAddr), Port:*alterPort})
	if err != nil {
		logger.Fatal("listen on PA failed")
	}

	if *isSlave && *alterAddr != "" {
		*alterAddr = ""
	}
	var aaAddr *net.UDPAddr
	if *alterAddr == "" {
		if *isSlave == false {
			if *slaveServer != "" {
				slaveAddr, err := net.ResolveTCPAddr("tcp", *slaveServer)
				if err != nil {
					logger.Fatal("slave server resolve failed")
				}
				slaveChan = make(chan *string, 128)
				go slaveClientWorker(slaveAddr)
				aaAddr = &net.UDPAddr{IP:slaveAddr.IP, Port:*alterPort}
			}
		} else if *slaveServer != "" {
			slaveAddr, err := net.ResolveTCPAddr("tcp", *slaveServer)
			if err != nil {
				logger.Fatal("slave server resolve failed")
			}
			go slaveWorker(slaveAddr)
		}
	} else {
		aaAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *alterAddr, *alterPort))
		if err != nil {
			logger.Fatalf("alterAddr %s:%d resolve failed", *alterAddr, alterPort)
		}
		roleSet[typeAP], err = net.ListenUDP("udp", &net.UDPAddr{IP:net.ParseIP(*alterAddr), Port:*primaryPort})
		if err != nil {
			logger.Fatal("listen on PP failed")
		}
		roleSet[typeAA], err = net.ListenUDP("udp", aaAddr)
		if err != nil {
			logger.Fatal("listen on PA failed")
		}

		go startStunServer(typeAP, roleSet[typeAP], nil)
		go startStunServer(typeAA, roleSet[typeAA], nil)
	}

	go startStunServer(typePA, roleSet[typePA], nil)
	startStunServer(typePP, roleSet[typePP], aaAddr)
}

func startStunServer(role int, conn *net.UDPConn, other *net.UDPAddr) {
	buf := make([]byte, 1500)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Println("receive Error: ", err)
		}
		var req stun.StunMessageReq
		if err = req.Unmarshal(buf[:n]); err != nil {
			logger.Println("receive error req: ", err.Error())
			continue
		}
		otherRole := role
		if req.ChangeIp {
			otherRole ^= 0x02
		}
		if req.ChangePort {
			otherRole ^= 0x01
		}
		if otherRole != role {
			if slaveChan != nil {
				info := fmt.Sprintf("%s|%x\n", remote.String(), req.TransacrtonId)
				go sendToSlave(&info)
				continue
			} else if *alterAddr != "" && roleSet[otherRole] != nil {
				if err = req.RespondTo(roleSet[otherRole], remote, nil); err != nil {
					logger.Printf("respond to %s failed %s", remote, err.Error())
				}
			} else {
				//ignore
				continue
			}
		} else {
			if err = req.RespondTo(conn, remote, other); err != nil {
				logger.Printf("respond to %s failed %s", remote, err.Error())
			}
		}
	}
}

func sendToSlave(info *string) {
	//ip:port|transactionId\n
	slaveChan <- info
}

func slaveClientWorker(slaveServer *net.TCPAddr) {

	for {
		conn, err := net.DialTCP("tcp", nil, slaveServer)
		if err != nil {
			logger.Fatal("Dial slave server failed:", err.Error())
		}

		for {
			data := <-slaveChan
			conn.SetNoDelay(true)
			_, err = conn.Write([]byte(*data))
			if err != nil {
				fmt.Println("Write to slave server failed:", err.Error())
				conn.Close()
				break
			}
		}
	}
}

func slaveWorker(slaveServer *net.TCPAddr) {
	l, err := net.ListenTCP("tcp", slaveServer)
	if err != nil {
		logger.Fatal("slave tcp listen error: ", err.Error())
		os.Exit(-1)
	}
	defer l.Close()

	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			logger.Fatal("slave accept error:", err.Error())
			continue
		}
		go slaveProcessRequest(conn)
	}
}

func slaveProcessRequest(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReaderSize(conn, 128)
	for {
		data, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Println("read from tcp socket failed:", err.Error())
			break
		}
		data = strings.TrimRight(data, "\n")
		logger.Println("slave get: ", data)
		infos := strings.Split(data, "|")
		if len(infos) != 2 {
			logger.Print("receive error slave data: ", data)
			continue
		}
		addr := infos[0]
		tid, err := hex.DecodeString(infos[1])
		if err != nil || len(tid) != 12 {
			logger.Print("receive error slave data: ", data)
			continue
		}
		remote, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			logger.Print("receive error slave data: ", data)
			continue
		}
		req := stun.NewBindRequest(tid)
		req.RespondTo(roleSet[typePP], remote, nil)
	}
}


package nat

import (
	"errors"
	"fmt"
	"github.com/bhpike65/go-stun/stun"
	"net"
)

const (
	NAT_TEST_FAILED = -1
	NAT_TYPE_NONAT  = iota
	NAT_TYPE_EIM    //Endpoint-Independent Mapping NAT
	NAT_TYPE_ADM    //Address-Dependent Mapping NAT
	NAT_TYPE_APDM   //Address and Port-Dependent Mapping NAT
	NAT_TYPE_EIF    //Endpoint-Independent Filtering NAT
	NAT_TYPE_ADF    //Address-Dependent Filtering NAT
	NAT_TYPE_APDF   //Address and Port-Dependent Filtering NAT
)

type NATBehaviorDiscovery struct {
	Local         *net.UDPAddr
	Server        *net.UDPAddr
	AltServer     *net.UDPAddr
	LocalAddr     string
	MappingAddr   string
	MappingType   int
	FilteringType int
	Hairpinning	  bool
}


func Discovery(local, server, altServer string) (*NATBehaviorDiscovery, error) {
	var res NATBehaviorDiscovery
	var err error
	res.Server, err = net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	res.Local, err = net.ResolveUDPAddr("udp", local)
	if err != nil {
		return nil, err
	}
	if altServer != "" {
		res.AltServer, err = net.ResolveUDPAddr("udp", altServer)
		if err != nil {
			return nil, err
		}
	}

	conn, err := net.ListenUDP("udp", res.Local)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res.LocalAddr = conn.LocalAddr().String()

	// testI: NO-NAT?
	req := stun.NewBindRequest(nil)
	resp, localAddr, err := req.RequestTo(conn, res.Server)
	if err != nil {
		return &res, errors.New(fmt.Sprintf("Failed to build STUN PP request: %s", err.Error()))
	}

	mappingPP := resp.Addr.String()
	res.MappingAddr = mappingPP

	if localAddr.String() == mappingPP {
		res.MappingType = NAT_TYPE_NONAT
		return &res, nil
	}
	primaryPort := res.Server.Port
	alternative := resp.OtherAddr
	other := resp.OtherAddr

	if other == nil && res.AltServer != nil {
		other = res.AltServer
	}
	if other != nil {
		altIp := other.IP
		altPort := other.Port
		// testII， send to alternativeIp:primaryPort
		req = stun.NewBindRequest(nil)
		remoteAP, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", altIp.String(), primaryPort))
		if err != nil {
			return &res, errors.New(fmt.Sprintf("resolve AP address failed:%s", err.Error()))
		}
		resp, localAddr, err = req.RequestTo(conn, remoteAP)
		if err != nil {
			return &res, errors.New(fmt.Sprintf("Failed to build STUN AP request:%s", err.Error()))
		}
		mappingAP := resp.Addr.String()
		if mappingPP == mappingAP {
			res.MappingType = NAT_TYPE_EIM
		} else {
			//testIII, send to alternativeIp:alternativePort
			req = stun.NewBindRequest(nil)
			remoteAA, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", altIp.String(), altPort))
			if err != nil {
				return &res, errors.New(fmt.Sprintf("resolve AA address failed:%s", err.Error()))
			}
			resp, localAddr, err = req.RequestTo(conn, remoteAA)
			if err != nil {
				return &res, errors.New(fmt.Sprintf("Failed to build STUN AA request:%s", err.Error()))
			}
			mappingAA := resp.Addr.String()
			if mappingAP == mappingAA {
				res.MappingType = NAT_TYPE_ADM
			} else {
				res.MappingType = NAT_TYPE_APDM
			}
		}
	} else {
		res.MappingType = NAT_TEST_FAILED
	}

	if alternative != nil {
		//start NAT filter behavior test
		//test II
		req = stun.NewBindRequest(nil)
		req.SetChangeIP(true)
		req.SetChangePort(true)
		_, _, err = req.RequestTo(conn, res.Server)
		if err == nil {
			res.FilteringType = NAT_TYPE_EIF
		} else {
			//test III
			req = stun.NewBindRequest(nil)
			req.SetChangeIP(false)
			req.SetChangePort(true)
			req.ValidateSource(fmt.Sprintf("%s:%d", res.Server.IP.String(), alternative.Port))
			resp, _, err = req.RequestTo(conn, res.Server)
			if err == nil {
				res.FilteringType = NAT_TYPE_ADF
			} else if resp != nil {
				res.FilteringType = NAT_TEST_FAILED
			} else {
				res.FilteringType = NAT_TYPE_APDF
			}
		}
	} else {
		res.FilteringType = NAT_TEST_FAILED
	}

	//hairpinning support test
	req = stun.NewBindRequest(nil)
	_, _, err = req.Request(res.Local.IP.String()+":0", mappingPP)
	if err == nil {
		res.Hairpinning = true
	}

	return &res, nil
}

func (d *NATBehaviorDiscovery) String() string {
	ret := fmt.Sprintf("localAddress:%s, mappingAddress:%s\n", d.LocalAddr, d.MappingAddr)
	switch d.MappingType {
	case NAT_TYPE_NONAT:
		ret += "NAT type: No NAT\n"
	case NAT_TYPE_EIM:
		ret += "NAT mapping type: Endpoint-Independent Mapping NAT\n"
	case NAT_TYPE_ADM:
		ret += "NAT mapping type: Address-Dependent Mapping NAT\n"
	case NAT_TYPE_APDM:
		ret += "NAT mapping type: Address and Port-Dependent Mapping NAT\n"
	case NAT_TEST_FAILED:
		ret += "NAT mapping type: test failed\n"
	}

	if d.MappingType != NAT_TYPE_NONAT {
		switch d.FilteringType {
		case NAT_TYPE_EIF:
			ret += "NAT filtering type: Endpoint-Independent Filtering NAT\n"
		case NAT_TYPE_ADF:
			ret += "NAT filtering type: Address-Dependent Filtering NAT\n"
		case NAT_TYPE_APDF:
			ret += "NAT filtering type: Address and Port-Dependent Filtering NAT\n"
		case NAT_TEST_FAILED:
			ret += "NAT filtering type: test failed\n"
		}
	}

	if d.Hairpinning {
		ret += "NAT Hairpinning Support: YES\n"
	} else {
		ret += "NAT Hairpinning Support:: NO\n"
	}

	return ret
}

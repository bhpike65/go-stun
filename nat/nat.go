package nat

import (
	"net"
	"github.com/bhpike65/go-stun/stun"
	"errors"
	"fmt"
)
const (
	NAT_TEST_FAILED = -1
	NAT_TYPE_NONAT = iota
	NAT_TYPE_EIM			//Endpoint-Independent Mapping NAT
	NAT_TYPE_ADM			//Address-Dependent Mapping NAT
	NAT_TYPE_APDM			//Address and Port-Dependent Mapping NAT
	NAT_TYPE_EIF			//Endpoint-Independent Filtering NAT
	NAT_TYPE_ADF			//Address-Dependent Filtering NAT
	NAT_TYPE_APDF			//Address and Port-Dependent Filtering NAT
)

type NATBehaviorDiscovery struct {
	Conn *net.UDPConn
	Local *net.UDPAddr
	Server *net.UDPAddr
	AltServer *net.UDPAddr
	LocalAddr   string
	MappingAddr string
	MappingType	  int
	FilteringType int
}

func NewNATDiscovery(localAddr, serverAddr, altServerAddr string) (*NATBehaviorDiscovery, error) {
	ret := new(NATBehaviorDiscovery)
	var err error
	ret.Server, err = net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	ret.Local, err = net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}
	ret.Conn, err = net.ListenUDP("udp", ret.Local)
	if err != nil {
		return nil, err
	}
	ret.LocalAddr = ret.Conn.LocalAddr().String()
	if altServerAddr != "" {
		ret.AltServer, err = net.ResolveUDPAddr("udp", altServerAddr)
		if err != nil {
			return nil, err
		}
	}
	ret.MappingType = NAT_TEST_FAILED
	ret.FilteringType = NAT_TEST_FAILED
	return ret, nil
}

func (d *NATBehaviorDiscovery) Discovery() error {
	// testI: NO-NAT?
	req := stun.NewBindRequest(nil)
	resp, localAddr, err := req.RequestTo(d.Conn, d.Server)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to build STUN PP request: %s", err.Error()))
	}

	if localAddr.String() == resp.Addr.String() {
		d.MappingType = NAT_TYPE_NONAT
		return nil
	}
	primaryPort := d.Server.Port
	mappingPP := resp.Addr.String()
	d.MappingAddr = mappingPP

	alternative := resp.OtherAddr
	other := resp.OtherAddr

	if other == nil && d.AltServer != nil {
		other = d.AltServer
	}
	if other != nil {
		altIp := other.IP
		altPort := other.Port
		// testII， send to alternativeIp:primaryPort
		req = stun.NewBindRequest(nil)
		remoteAP, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", altIp.String(), primaryPort))
		if err != nil {
			return errors.New(fmt.Sprintf("resolve AP address failed:%s", err.Error()))
		}
		resp, localAddr, err = req.RequestTo(d.Conn, remoteAP)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to build STUN AP request:%s", err.Error()))
		}
		mappingAP := resp.Addr.String()
		if mappingPP == mappingAP {
			d.MappingType = NAT_TYPE_EIM
		} else{
			//testIII, send to alternativeIp:alternativePort
			req = stun.NewBindRequest(nil)
			remoteAA, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", altIp.String(), altPort))
			if err != nil {
				return errors.New(fmt.Sprintf("resolve AA address failed:%s", err.Error()))
			}
			resp, localAddr, err = req.RequestTo(d.Conn, remoteAA)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to build STUN AA request:%s", err.Error()))
			}
			mappingAA := resp.Addr.String()
			if mappingAP == mappingAA {
				d.MappingType = NAT_TYPE_ADM
			} else {
				d.MappingType = NAT_TYPE_APDM
			}
		}
	} else {
		d.MappingType = NAT_TEST_FAILED
	}

	if alternative == nil {
		d.FilteringType = NAT_TEST_FAILED
		return nil
	}
	//start NAT filter behavior test
	//test II
	req = stun.NewBindRequest(nil)
	req.SetChangeIP(true)
	req.SetChangePort(true)
	_, _, err = req.RequestTo(d.Conn, d.Server)
	if err == nil {
		d.FilteringType = NAT_TYPE_EIF
	} else {
		//test III
		req = stun.NewBindRequest(nil)
		req.SetChangeIP(false)
		req.SetChangePort(true)
		req.ValidateSource(fmt.Sprintf("%s:%d", d.Server.IP.String(), alternative.Port))
		resp, _, err = req.RequestTo(d.Conn, d.Server)
		if err == nil {
			d.FilteringType = NAT_TYPE_ADF
		} else if resp != nil {
			d.FilteringType = NAT_TEST_FAILED
		} else {
			d.FilteringType = NAT_TYPE_APDF
		}
	}
	d.Conn.Close()
	return nil
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
	return ret
}

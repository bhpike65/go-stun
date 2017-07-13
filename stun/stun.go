package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"io"
	"net"
	"time"
)

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0|     STUN Message Type     |         Message Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Magic Cookie                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Transaction ID (96 bits)                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


                     0                 1
                     2  3  4 5 6 7 8 9 0 1 2 3 4 5

                    +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
                    |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
                    |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
                    +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 3: Format of STUN Message Type Field
*/

type header struct {
	Type          uint16
	Length        uint16
	Magic         uint32
	TransacrtonId [12]byte
}

type StunMessageReq struct {
	header

	ChangeIp   bool
	ChangePort bool
	RespSource string
	//Candidate	interface{}
}

type StunMessageResp struct {
	header
	Addr      *net.UDPAddr
	OtherAddr *net.UDPAddr
	ErrorCode uint16
	ErrorMsg  string
}

type attrHeader struct {
	Type   uint16
	Length uint16
}

const (
	// Comprehension required
	attrAddress       = 0x01
	attrChangeRequest = 0x03
	attrUsername      = 0x06
	attrIntegrity     = 0x08
	attrErrCode       = 0x09
	attrUnknownAttrs  = 0x0A
	attrRealm         = 0x14
	attrNonce         = 0x15
	attrXorAddress    = 0x20
	attrUseCandidate  = 0x25
	attrPadding       = 0x26
	attrResponsePort  = 0x27

	// Comprehension optional
	attrSoftware = 0x8022
	//attrAlternate   = 0x8023
	attrFingerprint  = 0x8028
	attrOtherAddress = 0x802c
)

const (
	errTryAlternate     = 300
	errBadRequest       = 400
	errUnauthorized     = 401
	errUnknownAttribute = 420
	errStaleNonce       = 438
	errServerInternal   = 500
)
const (
	classRequest = iota
	classIndication
	classResonseSuccess
	classError
	methodBinding = 1
)

const (
	attrAddressFieldIpv4 = 1
	attrAddressFieldIpv6 = 2
	attrAddressSizeIpv4  = 8
	attrAddressSizeIpv6  = 20
)

const (
	magic = 0x2112a442

	headerLen = 20
)

var (
	magicBytes = []byte{0x21, 0x12, 0xa4, 0x42}
)

func changeReqestValue(changeIp, changePort bool) uint32 {
	var v uint32
	if changeIp {
		v |= 0x04
	}
	if changePort {
		v |= 0x02
	}
	return v
}

func (req *StunMessageReq) Marshal() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, req.header)
	binary.Write(&buf, binary.BigEndian, []interface{}{
		uint16(attrChangeRequest),
		uint16(4),
		changeReqestValue(req.ChangeIp, req.ChangePort),
	})

	return buf.Bytes()
}

func (req *StunMessageReq) Unmarshal(data []byte) error {
	if err := binary.Read(bytes.NewBuffer(data[:headerLen]), binary.BigEndian, &req.header); err != nil {
		return err
	}

	if !typeIsRequest(req.Type) || methodFromMsgType(req.Type) != methodBinding ||
		req.Magic != magic ||
		int(req.Length+20) != len(data) {
		return errors.New("stun binding get an error format reply")
	}

	attrReader := bytes.NewBuffer(data[headerLen:])
	for {
		if attrReader.Len() == 0 {
			break
		}
		var ahdr attrHeader
		if err := binary.Read(attrReader, binary.BigEndian, &ahdr); err != nil {
			return err
		}

		value := attrReader.Next(int(ahdr.Length))
		if ahdr.Length%4 != 0 {
			attrReader.Next(int(4 - ahdr.Length%4))
		}

		switch ahdr.Type {
		case attrChangeRequest:
			req.ChangeIp = (binary.BigEndian.Uint32(value) & 0x04) != 0
			req.ChangePort = (binary.BigEndian.Uint32(value) & 0x02) != 0
		}
	}
	return nil
}

func (resp *StunMessageResp) Marshal() []byte {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, resp.header)
	if resp.Addr.IP.To4() != nil {
		binary.Write(&buf, binary.BigEndian, []interface{}{
			uint16(attrAddress),
			uint16(attrAddressSizeIpv4),
			uint8(0),
			uint8(attrAddressFieldIpv4),
			uint16(resp.Addr.Port),
			resp.Addr.IP.To4(),
		})

		binary.Write(&buf, binary.BigEndian, []interface{}{
			uint16(attrXorAddress),
			uint16(attrAddressSizeIpv4),
			uint8(0),
			uint8(attrAddressFieldIpv4),
			uint16(resp.Addr.Port ^ magic>>16),
		})
		for i, field := range resp.Addr.IP.To4() {
			binary.Write(&buf, binary.BigEndian, uint8(field^magicBytes[i]))
		}
	} else {
		binary.Write(&buf, binary.BigEndian, []interface{}{
			uint16(attrAddress),
			uint16(attrAddressSizeIpv6),
			uint8(0),
			uint8(attrAddressFieldIpv6),
			uint16(resp.Addr.Port),
			resp.Addr.IP.To16(),
		})
		binary.Write(&buf, binary.BigEndian, []interface{}{
			uint16(attrXorAddress),
			uint16(attrAddressSizeIpv6),
			uint8(0),
			uint8(attrAddressFieldIpv6),
			uint16(resp.Addr.Port ^ magic>>16),
		})
		for i, field := range resp.Addr.IP.To16() {
			if i < 4 {
				binary.Write(&buf, binary.BigEndian, uint8(field^magicBytes[i]))
			} else {
				binary.Write(&buf, binary.BigEndian, uint8(field^resp.TransacrtonId[i]))
			}
		}
	}

	if resp.OtherAddr != nil {
		if resp.OtherAddr.IP.To4() != nil {
			binary.Write(&buf, binary.BigEndian, []interface{}{
				uint16(attrOtherAddress),
				uint16(attrAddressSizeIpv4),
				uint8(0),
				uint8(attrAddressFieldIpv4),
				uint16(resp.OtherAddr.Port),
				resp.OtherAddr.IP.To4(),
			})
		} else {
			binary.Write(&buf, binary.BigEndian, []interface{}{
				uint16(attrOtherAddress),
				uint16(attrAddressSizeIpv6),
				uint8(0),
				uint8(attrAddressFieldIpv6),
				uint16(resp.OtherAddr.Port),
				resp.OtherAddr.IP.To16(),
			})
		}
	}

	resp.Length = uint16(len(buf.Bytes())) - 20
	buf.Bytes()[2] = byte(resp.Length >> 8)
	buf.Bytes()[3] = byte(resp.Length)

	return buf.Bytes()
}

func (resp *StunMessageResp) Unmarshal(data []byte) error {
	if err := binary.Read(bytes.NewBuffer(data[:headerLen]), binary.BigEndian, &resp.header); err != nil {
		return err
	}

	if !typeIsSuccessResp(resp.Type) || int(resp.Length+20) != len(data) || resp.Magic != magic {
		fmt.Println(resp.header)
		fmt.Println(typeIsSuccessResp(resp.Type), resp.Length, len(data))
		return errors.New("stun binding get an error format reply")
	}

	attrReader := bytes.NewBuffer(data[headerLen:])
	var haveXor bool
	for {
		if attrReader.Len() == 0 {
			break
		}

		var ahdr attrHeader
		if err := binary.Read(attrReader, binary.BigEndian, &ahdr); err != nil {
			return err
		}

		value := attrReader.Next(int(ahdr.Length))
		if ahdr.Length%4 != 0 {
			attrReader.Next(int(4 - ahdr.Length%4))
		}

		switch ahdr.Type {
		case attrAddress:
			if !haveXor {
				ip, port, err := parseAddress(value)
				if err != nil {
					return err
				}
				resp.Addr = &net.UDPAddr{IP: ip, Port: port, Zone: ""}
			}
		case attrXorAddress:
			ip, port, err := parseAddress(value)
			if err != nil {
				return err
			}
			for i := range ip {
				ip[i] ^= data[4+i]
			}
			port ^= int(binary.BigEndian.Uint16(data[4:]))
			resp.Addr = &net.UDPAddr{IP: ip, Port: port, Zone: ""}
			haveXor = true
		case attrErrCode:
			resp.ErrorCode = uint16(value[2])*100 + uint16(value[3])
			resp.ErrorMsg = string(value[4:])
		case attrOtherAddress:
			ip, port, err := parseAddress(value)
			if err != nil {
				return err
			}
			resp.OtherAddr = &net.UDPAddr{IP: ip, Port: port, Zone: ""}
		default:
		}
	}
	return nil
}

func parseAddress(raw []byte) (net.IP, int, error) {
	if len(raw) != 8 && len(raw) != 20 {
		return nil, 0, errors.New("address parse error")
	}
	var family int
	switch int(raw[1]) {
	case 1:
		family = 4
	case 2:
		family = 16
	default:
		return nil, 0, errors.New("address parse error")
	}
	port := binary.BigEndian.Uint16(raw[2:])
	ip := make([]byte, len(raw[4:]))
	copy(ip, raw[4:])
	if len(ip) != family {
		return nil, 0, errors.New("address parse error")
	}
	return net.IP(ip), int(port), nil
}

func getMsgType(class uint8, method uint16) uint16 {
	return (method&0x0f80)<<2 | (method&0x0070)<<1 | (method & 0x0f) | (uint16(class)&0x02)<<7 | (uint16(class)&0x01)<<4
}

func typeIsRequest(t uint16) bool {
	return (t & 0x0110) == 0x0000
}

func typeIsSuccessResp(t uint16) bool {
	return (t & 0x0110) == 0x0100
}
func typeIsErrorResp(t uint16) bool {
	return (t & 0x0110) == 0x0110
}

func methodFromMsgType(t uint16) uint16 {
	return (t & 0x000f) | ((t & 0x00e0) >> 1) | ((t & 0x3E00) >> 2)
}

func NewBindRequest(tid []byte) *StunMessageReq {
	var req StunMessageReq

	if tid == nil {
		tid = make([]byte, 12)
		_, err := io.ReadFull(rand.Reader, tid)
		if err != nil {
			return nil
		}
	}
	copy(req.TransacrtonId[:], tid)

	req.Type = getMsgType(classRequest, methodBinding)
	req.Length = 0
	req.Magic = magic

	return &req
}

func (req *StunMessageReq) SetChangeIP(on bool) {
	req.ChangeIp = on
}
func (req *StunMessageReq) SetChangePort(on bool) {
	req.ChangePort = on
}

func (req *StunMessageReq) ValidateSource(souce string) {
	req.RespSource = souce
}

func (req *StunMessageReq) RequestTo(conn *net.UDPConn, to *net.UDPAddr) (*StunMessageResp, *net.UDPAddr, error) {
	pkConn := ipv4.NewPacketConn(conn)
	pkConn.SetControlMessage(ipv4.FlagDst, true)

	if err := pkConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		fmt.Println("Couldn't set the socket timeout:", err)
	}

	loc, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())

	buf := make([]byte, 1500)
	for retry := 0; retry < 3; retry++ {
		_, err := pkConn.WriteTo(req.Marshal(), nil, to)
		if err != nil {
			return nil, nil, err
		}

		n, cm, src, err := pkConn.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {

			}
			return nil, nil, err
		}
		loc.IP = cm.Dst

		var resp StunMessageResp
		if err = resp.Unmarshal(buf[:n]); err != nil {
			return nil, loc, err
		}
		if req.RespSource != "" && src.String() != req.RespSource {
			return &resp, nil, errors.New("receive packet from unexpected source")
		}
		if resp.ErrorCode != 0 {
			return &resp, loc, errors.New(resp.ErrorMsg)
		}
		if req.TransacrtonId != resp.TransacrtonId ||
			getMsgType(classResonseSuccess, methodBinding) != resp.Type ||
			resp.Addr == nil {
			return &resp, loc, errors.New("receive error response")
		}
		return &resp, loc, nil
	}

	return nil, nil, errors.New("request retry exceeds max times")
}

func (req *StunMessageReq) Request(localAddr, remoteAddr string) (*StunMessageResp, *net.UDPAddr, error) {
	remote, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	local, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, nil, err
	}

	sock, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, nil, err
	}
	defer sock.Close()
	return req.RequestTo(sock, remote)
}

func (req *StunMessageReq) RespondTo(conn *net.UDPConn, to *net.UDPAddr, other *net.UDPAddr) error {
	var resp StunMessageResp

	resp.TransacrtonId = req.TransacrtonId
	resp.Type = getMsgType(classResonseSuccess, methodBinding)
	resp.Length = 0
	resp.Magic = magic
	resp.Addr = to
	resp.OtherAddr = other

	_, err := conn.WriteTo(resp.Marshal(), to)
	return err
}

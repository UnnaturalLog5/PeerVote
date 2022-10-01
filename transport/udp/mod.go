package udp

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"go.dedis.ch/cs438/transport"
)

const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	socket := Socket{
		udpConn: udpConn,
	}
	return &socket, nil
}

type packetStore struct {
	sync.RWMutex
	items []transport.Packet
}

func (p *packetStore) append(pkt transport.Packet) {
	p.Lock()
	defer p.Unlock()
	p.items = append(p.items, pkt)
}

func (p *packetStore) get() []transport.Packet {
	p.RLock()
	defer p.RUnlock()

	return p.items
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	udpConn     *net.UDPConn
	insPackets  packetStore
	outsPackets packetStore
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	return s.udpConn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	// Set deadline for timeouts > 0
	if timeout > 0 {
		err := s.udpConn.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			return err
		}
	}

	data, err := pkt.Marshal()
	if err != nil {
		return err
	}

	// resolve UDP addr from address string "dest"
	destAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return err
	}

	_, err = s.udpConn.WriteToUDP(data, destAddr)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return transport.TimeoutError(0)
	} else if err != nil {
		return err
	}

	s.outsPackets.append(pkt)

	return nil
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	if timeout > 0 {
		err := s.udpConn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return transport.Packet{}, err
		}
	}

	// QUESTION can we assume packets are smaller than bufSize?
	buf := make([]byte, bufSize)
	bytesRead, _, err := s.udpConn.ReadFromUDP(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return transport.Packet{}, transport.TimeoutError(0)
	} else if err != nil {
		return transport.Packet{}, err
	}

	var pkt transport.Packet

	err = pkt.Unmarshal(buf[:bytesRead])
	if err != nil {
		return transport.Packet{}, err
	}

	s.insPackets.append(pkt)

	return pkt, nil
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.udpConn.LocalAddr().String()
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	return s.insPackets.get()
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	return s.outsPackets.get()
}

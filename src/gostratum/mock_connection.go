package gostratum

import (
	"bufio"
	"net"
	"sync"
)

// MockConnection exercises real socket deadline and close semantics through net.Pipe.
// This avoids racing channel replacement against readers and deadline timers.
type MockConnection struct {
	net.Conn
	peer      net.Conn
	reader    *bufio.Reader
	closeOnce sync.Once
}

func NewMockConnection() *MockConnection {
	server, peer := net.Pipe()
	return &MockConnection{Conn: server, peer: peer, reader: bufio.NewReader(peer)}
}

func (mc *MockConnection) AsyncWriteTestDataToReadBuffer(s string) {
	go func() { _, _ = mc.peer.Write([]byte(s)) }()
}

func (mc *MockConnection) ReadTestDataFromBuffer(handler func([]byte)) {
	line, _ := mc.reader.ReadBytes('\n')
	handler(line)
}

func (mc *MockConnection) AsyncReadTestDataFromBuffer(handler func([]byte)) {
	go mc.ReadTestDataFromBuffer(handler)
}

func (mc *MockConnection) Close() error {
	mc.closeOnce.Do(func() { _ = mc.Conn.Close(); _ = mc.peer.Close() })
	return nil
}

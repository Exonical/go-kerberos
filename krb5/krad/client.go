package krad

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Client is a blocking RADIUS client. Datagram connections are retained and
// reused for requests with the same destination and shared secret.
type Client struct {
	mu        sync.Mutex
	conns     map[string]net.Conn
	connLocks map[string]*sync.Mutex
	ids       [256]bool
}

func NewClient() *Client { return &Client{conns: make(map[string]net.Conn)} }

func (c *Client) connection(ctx context.Context, network, address, secret string) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("nil RADIUS client")
	}
	key := network + "\x00" + address + "\x00" + secret
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conns == nil {
		c.conns = make(map[string]net.Conn)
	}
	if c.connLocks == nil {
		c.connLocks = make(map[string]*sync.Mutex)
	}
	if conn := c.conns[key]; conn != nil {
		return conn, nil
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	c.conns[key] = conn
	return conn, nil
}

func (c *Client) connectionLock(network, address, secret string) *sync.Mutex {
	key := network + "\x00" + address + "\x00" + secret
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connLocks == nil {
		c.connLocks = make(map[string]*sync.Mutex)
	}
	lock := c.connLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		c.connLocks[key] = lock
	}
	return lock
}

func (c *Client) forget(network, address, secret string, conn net.Conn) {
	if c == nil {
		return
	}
	key := network + "\x00" + address + "\x00" + secret
	c.mu.Lock()
	if current := c.conns[key]; current == conn {
		delete(c.conns, key)
		_ = current.Close()
	}
	c.mu.Unlock()
}

func (c *Client) Send(ctx context.Context, code Code, attrs *Attributes,
	server, secret string, timeout time.Duration, retries int) (*Packet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	request, err := NewRequest(code, attrs, secret)
	if err != nil {
		return nil, err
	}
	if err := c.reserveID(&request.ID); err != nil {
		return nil, err
	}
	defer c.releaseID(request.ID)
	if strings.HasPrefix(server, "/") {
		return c.sendStream(ctx, "unix", server, secret, request, timeout)
	}

	network := "udp"
	if strings.HasPrefix(server, "tcp://") {
		network, server = "tcp", strings.TrimPrefix(server, "tcp://")
	} else if strings.HasPrefix(server, "udp://") {
		server = strings.TrimPrefix(server, "udp://")
	} else if strings.HasPrefix(server, "tcp:") {
		network, server = "tcp", strings.TrimPrefix(server, "tcp:")
	}
	addresses, err := resolveAddresses(ctx, network, server)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("RADIUS server has no addresses")
	}
	perAddress := timeout / time.Duration(len(addresses))
	if perAddress <= 0 {
		perAddress = time.Nanosecond
	}
	for _, address := range addresses {
		var response *Packet
		if network == "tcp" {
			response, err = c.sendStream(ctx, network, address, secret, request, perAddress)
		} else {
			response, err = c.sendDatagram(ctx, address, secret, request, perAddress, retries)
		}
		if err == nil {
			return response, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, err
}

func (c *Client) reserveID(id *uint8) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := int(*id)
	for pass := 0; pass < 2; pass++ {
		if start%2 == 0 {
			for value := start; value < 256; value++ {
				if !c.ids[value] {
					c.ids[value] = true
					*id = uint8(value)
					return nil
				}
			}
		} else {
			for value := start; value >= 0; value-- {
				if !c.ids[value] {
					c.ids[value] = true
					*id = uint8(value)
					return nil
				}
			}
		}
		start = int(*id)
		if start%2 == 0 {
			for value := 0; value < start; value++ {
				if !c.ids[value] {
					c.ids[value] = true
					*id = uint8(value)
					return nil
				}
			}
		} else {
			for value := 255; value > start; value-- {
				if !c.ids[value] {
					c.ids[value] = true
					*id = uint8(value)
					return nil
				}
			}
		}
	}
	return errors.New("all RADIUS identifiers are in use")
}

func (c *Client) releaseID(id uint8) {
	c.mu.Lock()
	c.ids[id] = false
	c.mu.Unlock()
}

func resolveAddresses(ctx context.Context, network, server string) ([]string, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "1812"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, net.JoinHostPort(ip.String(), port))
	}
	return result, nil
}

func (c *Client) sendDatagram(ctx context.Context, address, secret string,
	request *Packet, timeout time.Duration, retries int) (*Packet, error) {
	conn, err := c.connection(ctx, "udp", address, secret)
	if err != nil {
		return nil, err
	}
	connLock := c.connectionLock("udp", address, secret)
	connLock.Lock()
	defer connLock.Unlock()
	wire, err := request.Bytes(secret)
	if err != nil {
		return nil, err
	}
	perAttempt := timeout / time.Duration(retries+1)
	if perAttempt <= 0 {
		perAttempt = time.Nanosecond
	}
	for attempt := 0; attempt <= retries; attempt++ {
		deadline := time.Now().Add(perAttempt)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			c.forget("udp", address, secret, conn)
			return nil, err
		}
		if _, err := conn.Write(wire); err != nil {
			c.forget("udp", address, secret, conn)
			return nil, err
		}
		for {
			buffer := make([]byte, PacketSizeMax)
			n, readErr := conn.Read(buffer)
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					break
				}
				c.forget("udp", address, secret, conn)
				return nil, readErr
			}
			response, decodeErr := DecodeResponse(buffer[:n], request, secret)
			if decodeErr == nil {
				return response, nil
			}
			// Unauthenticated or mismatched responses are ignored until the
			// attempt deadline expires, as required by libkrad.
		}
	}
	return nil, fmt.Errorf("RADIUS request timed out")
}

func (c *Client) sendStream(ctx context.Context, network, address, secret string,
	request *Packet, timeout time.Duration) (*Packet, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	wire, err := request.Bytes(secret)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	responseWire, err := ReadPacket(conn)
	if err != nil {
		return nil, err
	}
	return DecodeResponse(responseWire, request, secret)
}

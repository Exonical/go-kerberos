package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const DefaultMaxFrameSize uint32 = 16 << 20
const ResponseTooBigCode int32 = 52

func ReadTCPFrame(r io.Reader, max uint32) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("read TCP frame: nil reader")
	}
	if max == 0 {
		max = DefaultMaxFrameSize
	}
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read TCP frame length: %w", err)
	}
	if length > max {
		return nil, fmt.Errorf("read TCP frame: frame length %d exceeds maximum %d", length, max)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read TCP frame payload: %w", err)
	}
	return payload, nil
}

func WriteTCPFrame(w io.Writer, payload []byte) error {
	if w == nil {
		return fmt.Errorf("write TCP frame: nil writer")
	}
	if uint64(len(payload)) > uint64(^uint32(0)) {
		return fmt.Errorf("write TCP frame: payload too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writeFull(w, header[:]); err != nil {
		return fmt.Errorf("write TCP frame length: %w", err)
	}
	if _, err := writeFull(w, payload); err != nil {
		return fmt.Errorf("write TCP frame payload: %w", err)
	}
	return nil
}

type Exchange struct {
	MaxFrameSize       uint32
	UDPPreferenceLimit int
	Timeout            time.Duration
	Dialer             Dialer
}

// Dialer opens the TCP connection used when UDP cannot carry a request or
// returns KRB_ERR_RESPONSE_TOO_BIG.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func (e Exchange) Request(ctx context.Context, conn net.PacketConn, address net.Addr, payload []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("transport request: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("transport request: %w", err)
	}
	if conn == nil {
		return nil, fmt.Errorf("transport request: nil packet connection")
	}
	if address == nil {
		return nil, fmt.Errorf("transport request: nil address")
	}
	max := e.MaxFrameSize
	if max == 0 {
		max = DefaultMaxFrameSize
	}
	limit := e.UDPPreferenceLimit
	if limit <= 0 {
		limit = 1400
	}
	if len(payload) > limit {
		return e.requestTCP(ctx, address.String(), payload, max)
	}
	requestConn := conn
	var temporaryUDP *net.UDPConn
	if udp, ok := conn.(*net.UDPConn); ok && udp.LocalAddr().String() == address.String() {
		var listenErr error
		temporaryUDP, listenErr = net.ListenUDP("udp", nil)
		if listenErr != nil {
			return nil, fmt.Errorf("UDP socket: %w", listenErr)
		}
		defer temporaryUDP.Close()
		requestConn = temporaryUDP
	}
	response, err := e.requestUDP(ctx, requestConn, address, payload, max)
	if err != nil {
		return nil, err
	}
	if responseTooBig(response) {
		return e.requestTCP(ctx, address.String(), payload, max)
	}
	return response, nil
}

func (e Exchange) requestUDP(ctx context.Context, conn net.PacketConn, address net.Addr, payload []byte, max uint32) ([]byte, error) {
	if deadline, ok := contextDeadline(ctx, e.Timeout); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if _, err := conn.WriteTo(payload, address); err != nil {
		return nil, fmt.Errorf("UDP request: %w", err)
	}
	bufferSize, err := boundedBufferSize(max)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, bufferSize)
	start := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("UDP response: %w", err)
		}
		deadline, hasDeadline := contextDeadline(ctx, e.Timeout)
		if !hasDeadline {
			deadline = time.Now().Add(50 * time.Millisecond)
		} else if time.Until(deadline) <= 0 {
			return nil, fmt.Errorf("UDP response: %w", context.DeadlineExceeded)
		}
		_ = conn.SetReadDeadline(deadline)
		n, _, readErr := conn.ReadFrom(buffer)
		if readErr == nil {
			if uint32(n) > max {
				return nil, fmt.Errorf("UDP response exceeds maximum frame size %d", max)
			}
			return append([]byte(nil), buffer[:n]...), nil
		}
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			if e.Timeout > 0 && time.Since(start) >= e.Timeout {
				return nil, fmt.Errorf("UDP response: %w", context.DeadlineExceeded)
			}
			continue
		}
		return nil, fmt.Errorf("UDP response: %w", readErr)
	}
}

func (e Exchange) requestTCP(ctx context.Context, address string, payload []byte, max uint32) ([]byte, error) {
	dialer := e.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP connection: %w", err)
	}
	defer conn.Close()
	stopClose := make(chan struct{})
	defer close(stopClose)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopClose:
		}
	}()
	if deadline, ok := contextDeadline(ctx, e.Timeout); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := WriteTCPFrame(conn, payload); err != nil {
		return nil, fmt.Errorf("TCP request: %w", err)
	}
	response, err := ReadTCPFrame(conn, max)
	if err != nil {
		return nil, fmt.Errorf("TCP response: %w", err)
	}
	return response, nil
}

func contextDeadline(ctx context.Context, timeout time.Duration) (time.Time, bool) {
	deadline, hasDeadline := ctx.Deadline()
	if timeout > 0 {
		timeoutDeadline := time.Now().Add(timeout)
		if !hasDeadline || timeoutDeadline.Before(deadline) {
			deadline, hasDeadline = timeoutDeadline, true
		}
	}
	return deadline, hasDeadline
}

func boundedBufferSize(max uint32) (int, error) {
	maxInt := int(^uint(0) >> 1)
	if uint64(max)+1 > uint64(maxInt) {
		return 0, fmt.Errorf("transport frame limit is too large")
	}
	return int(max) + 1, nil
}

func writeFull(w io.Writer, data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return total, fmt.Errorf("invalid writer count %d", n)
		}
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func responseTooBig(data []byte) bool {
	if len(data) < 2 || data[0] != 0x7e {
		return false
	}
	length, content, _, ok := derContent(data)
	if !ok || length != len(content) {
		return false
	}
	return containsErrorCode(content)
}

func containsErrorCode(data []byte) bool {
	for len(data) > 0 {
		if len(data) < 2 {
			return false
		}
		tag := data[0]
		length, content, headerLength, ok := derContent(data)
		if !ok {
			return false
		}
		if tag == 0xa6 && len(content) == 3 &&
			content[0] == 0x02 && content[1] == 0x01 && content[2] == byte(ResponseTooBigCode) {
			return true
		}
		if tag&0x20 != 0 && containsErrorCode(content) {
			return true
		}
		data = data[headerLength+length:]
	}
	return false
}

func derContent(data []byte) (int, []byte, int, bool) {
	if len(data) < 2 {
		return 0, nil, 0, false
	}
	first := data[1]
	offset := 2
	var length int
	switch {
	case first < 0x80:
		length = int(first)
	case first == 0x80:
		return 0, nil, 0, false
	default:
		count := int(first & 0x7f)
		if count == 0 || count > 4 || len(data) < offset+count {
			return 0, nil, 0, false
		}
		if data[offset] == 0 {
			return 0, nil, 0, false
		}
		for i := 0; i < count; i++ {
			length = length<<8 | int(data[offset+i])
		}
		if length < 0x80 {
			return 0, nil, 0, false
		}
		offset += count
	}
	if length < 0 || length > len(data)-offset {
		return 0, nil, 0, false
	}
	return length, data[offset : offset+length], offset, true
}

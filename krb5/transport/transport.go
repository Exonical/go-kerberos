package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

const DefaultMaxFrameSize uint32 = 16 << 20
const ResponseTooBigCode int32 = 52

func ReadTCPFrame(r io.Reader, max uint32) ([]byte, error) {
	_, _ = r, max
	return nil, fmt.Errorf("read TCP frame: %w", krberrors.ErrNotImplemented)
}

func WriteTCPFrame(w io.Writer, payload []byte) error {
	_, _ = w, payload
	return fmt.Errorf("write TCP frame: %w", krberrors.ErrNotImplemented)
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
	_, _, _, _ = ctx, conn, address, payload
	return nil, fmt.Errorf("transport request: %w", krberrors.ErrNotImplemented)
}

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
}

func (e Exchange) Request(ctx context.Context, conn net.PacketConn, address net.Addr, payload []byte) ([]byte, error) {
	_, _, _, _ = ctx, conn, address, payload
	return nil, fmt.Errorf("transport request: %w", krberrors.ErrNotImplemented)
}

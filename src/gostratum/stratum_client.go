package gostratum

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// maxLineSize caps a single stratum line. A v3 submit carries a hex-encoded PoM
// proof, so lines can be large; mirrors the miner's 2MB codec limit.
const maxLineSize = 2 * 1024 * 1024

func spawnClientListener(ctx *StratumContext, connection net.Conn, s *StratumListener) error {
	defer ctx.Disconnect()
	stop := context.AfterFunc(ctx.parentContext, func() { connection.Close() })
	defer stop()

	reader := bufio.NewReaderSize(connection, 64*1024)
	pending := make([]byte, 0, 1024)
	connectedAt := time.Now()
	frameStarted := connectedAt
	for {
		if !ctx.IsAuthorized() && time.Since(connectedAt) > 30*time.Second {
			return errors.New("authorization deadline exceeded")
		}
		if len(pending) == 0 {
			frameStarted = time.Now()
		} else if time.Since(frameStarted) > 30*time.Second {
			return errors.New("frame deadline exceeded")
		}
		deadline := time.Now().Add(5 * time.Second).UTC()
		if err := connection.SetReadDeadline(deadline); err != nil {
			return err
		}
		chunk, err := reader.ReadSlice('\n')
		// Partial lines survive read deadlines: keep accumulating until the newline.
		if len(pending)+len(chunk) > maxLineSize {
			return errors.Errorf("stratum line exceeds %d bytes", maxLineSize)
		}
		pending = append(pending, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
				if len(pending) > maxLineSize {
					return errors.Errorf("stratum line exceeds %d bytes", maxLineSize)
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if ctx.parentContext.Err() != nil {
					return ctx.parentContext.Err()
				}
				continue
			}
			ctx.Logger.Error("error reading from socket", zap.Error(err))
			return errors.Wrap(err, "error reading from connection")
		}
		if len(pending) > maxLineSize {
			return errors.Errorf("stratum line exceeds %d bytes", maxLineSize)
		}
		line := string(bytes.Trim(pending, " \r\n"))
		pending = pending[:0]
		if len(line) == 0 {
			continue
		}
		event, err := UnmarshalEvent(line)
		if err != nil {
			ctx.Logger.Error("error unmarshalling event")
			return err
		}
		if err := s.HandleEvent(ctx, event); err != nil {
			return err
		}
	}
}

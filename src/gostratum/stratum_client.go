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

	reader := bufio.NewReaderSize(connection, 64*1024)
	pending := make([]byte, 0, 1024)
	for {
		deadline := time.Now().Add(5 * time.Second).UTC()
		if err := connection.SetReadDeadline(deadline); err != nil {
			return err
		}
		chunk, err := reader.ReadBytes('\n')
		// Partial lines survive read deadlines: keep accumulating until the newline.
		pending = append(pending, chunk...)
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
		line := string(bytes.Trim(bytes.ReplaceAll(pending, []byte("\x00"), nil), " \r\n"))
		pending = pending[:0]
		if len(line) == 0 {
			continue
		}
		event, err := UnmarshalEvent(line)
		if err != nil {
			ctx.Logger.Error("error unmarshalling event", zap.String("raw", line))
			return err
		}
		if err := s.HandleEvent(ctx, event); err != nil {
			return err
		}
	}
}

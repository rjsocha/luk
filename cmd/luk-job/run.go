package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"luk/internal/runproto"
)

// exitCode ends luk-job with the code and no message.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// askRun asks lukd run for job on work and relays its output; luk-job exits
// with the job's exit status. A cancelled ctx closes the connection, which
// makes lukd run stop the job.
func askRun(ctx context.Context, socket, job, work string, stdout, stderr io.Writer) error {
	err := runproto.Ask(ctx, socket, job, work, stdout, stderr)
	var ee runproto.ExitError
	if errors.As(err, &ee) {
		return exitCode(ee)
	}
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}

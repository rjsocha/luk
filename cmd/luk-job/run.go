package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"luk/internal/runproto"
	"luk/internal/runstep"
)

// exitCode ends luk-job with the code and no message.
type exitCode int

func (c exitCode) Error() string { return fmt.Sprintf("exit status %d", int(c)) }

// askRun asks lukd run for job on work, passing on the metadata of
// luk-job's own environment (the LUK_* variables of the run step), and
// relays its output; luk-job exits with the job's exit status. A
// cancelled ctx closes the connection, which makes lukd run stop the job.
func askRun(ctx context.Context, socket, job, work string, stdout, stderr io.Writer) error {
	req := runproto.Request{Job: job, Work: work, Env: runstep.Meta(work, os.LookupEnv)}
	err := runproto.Ask(ctx, socket, req, stdout, stderr)
	var ee runproto.ExitError
	if errors.As(err, &ee) {
		return exitCode(ee)
	}
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return nil
}

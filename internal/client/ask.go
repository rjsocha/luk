package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/term"
)

// AskSecret reads a line from the terminal, echoing '*' per character.
func AskSecret(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("--secret needs a terminal: %w", err)
	}
	defer tty.Close()
	fd := int(tty.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, old)
	fmt.Fprint(tty, prompt)
	return readMasked(tty, tty)
}

func readMasked(r io.Reader, w io.Writer) ([]byte, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 0 {
			if err == io.EOF {
				fmt.Fprint(w, "\r\n")
				return buf, nil
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		switch c := b[0]; {
		case c == '\r' || c == '\n':
			fmt.Fprint(w, "\r\n")
			return buf, nil
		case c == 3:
			fmt.Fprint(w, "\r\n")
			return nil, errors.New("interrupted")
		case c == 4 && len(buf) == 0:
			fmt.Fprint(w, "\r\n")
			return buf, nil
		case c == 127 || c == 8:
			if len(buf) > 0 {
				_, size := utf8.DecodeLastRune(buf)
				buf = buf[:len(buf)-size]
				fmt.Fprint(w, "\b \b")
			}
		case c < 32:
		default:
			buf = append(buf, c)
			if c&0xC0 != 0x80 { // one star per character, not per byte
				fmt.Fprint(w, "*")
			}
		}
	}
}

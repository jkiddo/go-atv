package simulator

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

// readLabMessage bounds headers independently from the body and preserves
// pipelined bytes. Duplicate lengths and transfer encodings are ambiguous.
func readLabMessage(r *bufio.Reader) (string, textproto.MIMEHeader, []byte, error) {
	remaining := 16 * 1024
	line := func() (string, error) {
		var b []byte
		for {
			part, err := r.ReadSlice('\n')
			remaining -= len(part)
			if remaining < 0 {
				return "", errors.New("lab headers too large")
			}
			b = append(b, part...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return "", err
			}
			if !bytes.HasSuffix(b, []byte("\r\n")) {
				return "", errors.New("invalid lab line ending")
			}
			return string(b[:len(b)-2]), nil
		}
	}
	first, err := line()
	if err != nil {
		return "", nil, nil, err
	}
	headers := make(textproto.MIMEHeader)
	for {
		s, e := line()
		if e != nil {
			return "", nil, nil, e
		}
		if s == "" {
			break
		}
		key, value, ok := strings.Cut(s, ":")
		if !ok || strings.TrimSpace(key) != key || key == "" {
			return "", nil, nil, errors.New("invalid lab header")
		}
		headers.Add(key, strings.TrimSpace(value))
	}
	if len(headers.Values("Content-Length")) > 1 || headers.Get("Transfer-Encoding") != "" {
		return "", nil, nil, errors.New("ambiguous lab framing")
	}
	size := 0
	if value := headers.Get("Content-Length"); value != "" {
		size, err = strconv.Atoi(value)
		if err != nil || size < 0 || size > 1<<20 {
			return "", nil, nil, errors.New("invalid lab body length")
		}
	}
	body := make([]byte, size)
	_, err = io.ReadFull(r, body)
	return first, headers, body, err
}
func labInt(v any) (int, bool) {
	switch x := v.(type) {
	case uint64:
		if x <= 65535 {
			return int(x), true
		}
	case int64:
		if x >= 0 && x <= 65535 {
			return int(x), true
		}
	case int:
		return x, true
	}
	return 0, false
}

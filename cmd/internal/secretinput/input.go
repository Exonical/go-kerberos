package secretinput

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Read reads a secret without terminal echo when input is an interactive tty.
func Read(stdin io.Reader, stderr io.Writer, prompt string, interactive bool) (string, error) {
	fmt.Fprint(stderr, prompt)
	if interactive {
		if file, ok := stdin.(*os.File); ok {
			value, err := term.ReadPassword(int(file.Fd()))
			fmt.Fprintln(stderr)
			if err != nil {
				return "", fmt.Errorf("read secret: %w", err)
			}
			if len(value) == 0 {
				return "", fmt.Errorf("empty secret")
			}
			return string(value), nil
		}
	}
	value, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read secret: %w", err)
	}
	value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
	if value == "" {
		return "", fmt.Errorf("empty secret")
	}
	return value, nil
}

func IsTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

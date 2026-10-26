package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var releaseTag = regexp.MustCompile(`^v1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.[1-9][0-9]*)?$`)

func releaseNotes(tag, changelog string) (string, error) {
	if !releaseTag.MatchString(tag) {
		return "", errors.New("expected v1.X.Y or v1.X.Y-{alpha,beta,rc}.N")
	}
	var lines []string
	found, collecting := false, false
	for line := range strings.SplitSeq(changelog, "\n") {
		if strings.HasPrefix(line, "## ") {
			collecting = line == "## "+tag
			if collecting {
				if found {
					return "", fmt.Errorf("duplicate changelog entry for %s", tag)
				}
				found = true
			}
			continue
		}
		if collecting {
			lines = append(lines, line)
		}
	}
	notes := strings.TrimSpace(strings.Join(lines, "\n"))
	if !found || notes == "" {
		return "", fmt.Errorf("missing or empty changelog entry for %s", tag)
	}
	return notes + "\n", nil
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: go run ./internal/release TAG")
	}
	changelog, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		return err
	}
	notes, err := releaseNotes(args[0], string(changelog))
	if err != nil {
		return err
	}
	_, err = fmt.Print(notes)
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

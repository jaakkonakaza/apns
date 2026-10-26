package payload_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestActivityPayloadRejectsWrongStateAtCompileTime(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(t.TempDir(), "wrong-state"), "./testdata/wrong_state")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("compilation did not finish: %v", ctx.Err())
	}
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("expected compiler rejection, got error=%v output=%s", err, output)
	}
	// Match only the position and the type names from the fixture, not the
	// compiler's wording, which can change between Go releases.
	source, err := os.ReadFile("testdata/wrong_state/main.go")
	if err != nil {
		t.Fatal(err)
	}
	line := slices.IndexFunc(strings.Split(string(source), "\n"), func(s string) bool {
		return strings.HasPrefix(s, "var _ = payload.ActivityUpdate")
	}) + 1
	if line == 0 {
		t.Fatal("fixture is missing its mismatched payload")
	}
	position := fmt.Sprintf("main.go:%d:", line)
	for diagnostic := range strings.Lines(string(output)) {
		if strings.Contains(diagnostic, position) && strings.Contains(diagnostic, "OtherState") && strings.Contains(diagnostic, "OrderState") {
			return
		}
	}
	t.Fatalf("compilation failed for an unexpected reason; want a %s error about OtherState and OrderState in:\n%s", position, output)
}

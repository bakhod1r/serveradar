package execx

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunMissingTool(t *testing.T) {
	_, err := Run(context.Background(), time.Second, "definitely-not-a-real-tool-xyz")
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("want ErrMissing, got %v", err)
	}
}

func TestRunTimeout(t *testing.T) {
	_, err := Run(context.Background(), 50*time.Millisecond, "sleep", "2")
	if err == nil {
		t.Fatal("want timeout error")
	}
}

package airplay

import (
	"errors"
	"strings"
	"testing"
)

func TestStatusErrorBusyHint(t *testing.T) {
	busy := &StatusError{What: "POST /play", Code: 453, Message: "Not Enough Bandwidth"}
	if !IsBusy(busy) || IsAuthFailure(busy) || !strings.Contains(busy.Error(), "another AirPlay connection") {
		t.Fatalf("busy error misclassified: %v", busy)
	}
	other := &StatusError{What: "POST /play", Code: 500, Message: "x"}
	if IsBusy(other) || strings.Contains(other.Error(), "busy") {
		t.Fatalf("non-453 error flagged busy: %v", other)
	}
	if IsBusy(errors.New("x")) {
		t.Fatal("plain error flagged busy")
	}
}

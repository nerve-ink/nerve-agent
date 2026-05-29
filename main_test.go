package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestShouldHandleEnvelopeOnlyCommands(t *testing.T) {
	cases := []struct {
		name string
		env  Envelope
		want bool
	}{
		{name: "command", env: Envelope{Kind: "command"}, want: true},
		{name: "agent reply", env: Envelope{Kind: "agent_reply"}, want: false},
		{name: "plain message", env: Envelope{Kind: "message"}, want: false},
		{name: "missing kind", env: Envelope{}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldHandleEnvelope(tc.env); got != tc.want {
				t.Fatalf("shouldHandleEnvelope(%q) = %v, want %v", tc.env.Kind, got, tc.want)
			}
		})
	}
}

func TestEnvelopeDecodesKind(t *testing.T) {
	raw := []byte(`{"kind":"command","payload_raw":"{}"}`)
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Kind != "command" {
		t.Fatalf("kind = %q, want command", env.Kind)
	}
}

func TestUpdateKeyringSkipsMalformedKeys(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	updateKeyring([]string{"not-base64", good})
	defer updateKeyring(nil)

	if len(trustedKeys) != 1 {
		t.Fatalf("trustedKeys len = %d, want 1", len(trustedKeys))
	}
	if _, ok := trustedKeys[good]; !ok {
		t.Fatalf("trusted key %q was not installed", good)
	}
}

func TestCommandReplyOutputAlwaysReturnsVisibleText(t *testing.T) {
	if got := commandReplyOutput("", false, 512*1024, false, time.Second, nil); got != "[Command completed with no output]" {
		t.Fatalf("empty output = %q", got)
	}

	got := commandReplyOutput("stdout", true, 512*1024, false, time.Second, errors.New("exit status 1"))
	if want := "stdout\n[Output truncated at 512KB]\nError: exit status 1"; got != want {
		t.Fatalf("command output = %q, want %q", got, want)
	}
}

func TestHandlerReplyOutputAlwaysReturnsVisibleText(t *testing.T) {
	if got := handlerReplyOutput("  \n", false, 512*1024, false, nil); got != "[Handler completed with no output]" {
		t.Fatalf("empty handler output = %q", got)
	}

	got := handlerReplyOutput("partial", false, 512*1024, true, nil)
	if want := "partial\n[Error] Handler timed out (30s limit)."; got != want {
		t.Fatalf("handler timeout output = %q, want %q", got, want)
	}
}

func TestPreviewDoesNotPanicOnShortValues(t *testing.T) {
	if got := preview("abc", 8); got != "abc" {
		t.Fatalf("short preview = %q", got)
	}
	if got := preview("abcdefghijk", 8); got != "abcdefgh" {
		t.Fatalf("long preview = %q", got)
	}
}

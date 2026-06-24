package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
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
		{name: "byte stream request", env: Envelope{Kind: "byte_stream_request"}, want: true},
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

func TestCommandECDHKDFVector(t *testing.T) {
	aliceRaw := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	}
	bobRaw := []byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	}

	alice, err := ecdh.X25519().NewPrivateKey(aliceRaw)
	if err != nil {
		t.Fatalf("alice private key: %v", err)
	}
	bob, err := ecdh.X25519().NewPrivateKey(bobRaw)
	if err != nil {
		t.Fatalf("bob private key: %v", err)
	}

	oldKey := ecdhPrivKey
	ecdhPrivKey = alice
	defer func() { ecdhPrivKey = oldKey }()

	bobPubB64 := base64.StdEncoding.EncodeToString(bob.PublicKey().Bytes())
	got, err := deriveSharedKey(bobPubB64)
	if err != nil {
		t.Fatalf("derive shared key: %v", err)
	}
	gotB64 := base64.StdEncoding.EncodeToString(got)
	const wantB64 = "qqieCAodYNDWvV6z2JNvuJECaJXHpRHIWniQDtbxop8="
	if gotB64 != wantB64 {
		t.Fatalf("derived key = %q, want %q", gotB64, wantB64)
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

	got = commandReplyOutput("partial", false, 512*1024, true, 30*time.Second, errors.New("signal: killed"))
	if want := "[Error] Command timed out (30s limit).\npartial"; got != want {
		t.Fatalf("command timeout output = %q, want %q", got, want)
	}
}

func TestHandlerReplyOutputAlwaysReturnsVisibleText(t *testing.T) {
	if got := handlerReplyOutput("  \n", false, 512*1024, false, 30*time.Second, nil); got != "[Handler completed with no output]" {
		t.Fatalf("empty handler output = %q", got)
	}

	got := handlerReplyOutput("partial", false, 512*1024, true, 30*time.Second, nil)
	if want := "[Error] Handler timed out (30s limit).\npartial"; got != want {
		t.Fatalf("handler timeout output = %q, want %q", got, want)
	}
}

func TestExecutionSeverity(t *testing.T) {
	if got := executionSeverity(false, nil); got != "info" {
		t.Fatalf("success severity = %q", got)
	}
	if got := executionSeverity(true, nil); got != "error" {
		t.Fatalf("timeout severity = %q", got)
	}
	if got := executionSeverity(false, errors.New("exit status 1")); got != "error" {
		t.Fatalf("error severity = %q", got)
	}
}

func TestFormatDialErrorIncludesHandshakeStatus(t *testing.T) {
	resp := &http.Response{
		Status: "409 Conflict",
		Body:   io.NopCloser(strings.NewReader("Agent already connected\n")),
	}
	got := formatDialError(errors.New("websocket: bad handshake"), resp)
	if !strings.Contains(got, "409 Conflict") {
		t.Fatalf("dial error missing status: %q", got)
	}
	if !strings.Contains(got, "Agent already connected") {
		t.Fatalf("dial error missing response body: %q", got)
	}
}

func TestRunProcessWithTimeoutKillsLongRunningCommand(t *testing.T) {
	start := time.Now()
	output, truncated, timedOut, err := runProcessWithTimeout(100*time.Millisecond, 512*1024, nil, "sh", "-c", "sleep 5; echo done")

	if !timedOut {
		t.Fatalf("timedOut = false, err=%v output=%q", err, output)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
	if truncated {
		t.Fatalf("truncated = true")
	}
	if strings.Contains(output, "done") {
		t.Fatalf("command continued after timeout: %q", output)
	}
}

func TestRunProcessWithTimeoutTruncatesOutput(t *testing.T) {
	output, truncated, timedOut, err := runProcessWithTimeout(time.Second, 4, nil, "sh", "-c", "printf abcdef")

	if err != nil {
		t.Fatalf("run process: %v", err)
	}
	if timedOut {
		t.Fatalf("timedOut = true")
	}
	if !truncated {
		t.Fatalf("truncated = false")
	}
	if output != "abcd" {
		t.Fatalf("output = %q, want %q", output, "abcd")
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

package main

import (
	"crypto/ecdh"
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

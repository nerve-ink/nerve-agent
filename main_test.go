package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

func TestValidateByteStreamRequest(t *testing.T) {
	now := time.UnixMilli(1_800_000)
	valid := byteStreamRequestPayload{
		StreamID: "03d651b2-dd3e-4cb8-a0c1-e6e5afba046a",
		RouteID:  "9c77044a-934d-4381-a691-c7d7a2e86e07",
		Ts:       now.UnixMilli(),
	}
	if err := validateByteStreamRequest(valid, now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []struct {
		name string
		req  byteStreamRequestPayload
	}{
		{name: "expired", req: byteStreamRequestPayload{StreamID: valid.StreamID, RouteID: valid.RouteID, Ts: now.Add(-31 * time.Second).UnixMilli()}},
		{name: "future", req: byteStreamRequestPayload{StreamID: valid.StreamID, RouteID: valid.RouteID, Ts: now.Add(11 * time.Second).UnixMilli()}},
		{name: "missing stream", req: byteStreamRequestPayload{RouteID: valid.RouteID, Ts: now.UnixMilli()}},
		{name: "missing route", req: byteStreamRequestPayload{StreamID: valid.StreamID, Ts: now.UnixMilli()}},
		{name: "invalid stream", req: byteStreamRequestPayload{StreamID: "stream-1", RouteID: valid.RouteID, Ts: now.UnixMilli()}},
		{name: "invalid route", req: byteStreamRequestPayload{StreamID: valid.StreamID, RouteID: "route-1", Ts: now.UnixMilli()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateByteStreamRequest(tc.req, now); err == nil {
				t.Fatalf("invalid request was accepted: %#v", tc.req)
			}
		})
	}
}

func TestDecodeByteStreamRequestPayloadRejectsUnknownFields(t *testing.T) {
	now := time.UnixMilli(1_800_000)
	raw := fmt.Sprintf(
		`{"stream_id":"03d651b2-dd3e-4cb8-a0c1-e6e5afba046a","route_id":"9c77044a-934d-4381-a691-c7d7a2e86e07","ts":%d,"cmd":"printf ok"}`,
		now.UnixMilli(),
	)
	req, err := decodeByteStreamRequestPayload(raw)
	if err != nil {
		t.Fatalf("decode valid byte stream request: %v", err)
	}
	if req.StreamID == "" || req.RouteID == "" || req.Ts != now.UnixMilli() || req.Cmd != "printf ok" {
		t.Fatalf("decoded request = %#v", req)
	}

	withUnknown := fmt.Sprintf(
		`{"stream_id":"03d651b2-dd3e-4cb8-a0c1-e6e5afba046a","route_id":"9c77044a-934d-4381-a691-c7d7a2e86e07","ts":%d,"filename":"secret.txt"}`,
		now.UnixMilli(),
	)
	if _, err := decodeByteStreamRequestPayload(withUnknown); err == nil {
		t.Fatal("byte stream request with unknown field was accepted")
	}
	if _, err := decodeByteStreamRequestPayload(raw + `{}`); err == nil {
		t.Fatal("byte stream request with trailing JSON was accepted")
	}
}

func TestSplitByteStreamChunks(t *testing.T) {
	chunks := splitByteStreamChunks("abcdef", 2)
	want := []string{"ab", "cd", "ef"}
	if !reflect.DeepEqual(chunks, want) {
		t.Fatalf("chunks = %#v, want %#v", chunks, want)
	}
	if got := splitByteStreamChunks("", 2); len(got) != 1 || got[0] != "[empty byte stream]" {
		t.Fatalf("empty chunks = %#v", got)
	}
}

func TestByteStreamChunksForRequestUsesCommandOutput(t *testing.T) {
	oldTimeout, oldMaxOutputBytes := cmdTimeout, maxOutputBytes
	cmdTimeout, maxOutputBytes = 5*time.Second, 512*1024
	defer func() {
		cmdTimeout, maxOutputBytes = oldTimeout, oldMaxOutputBytes
	}()

	chunks, err := byteStreamChunksForRequest(byteStreamRequestPayload{Cmd: "printf byte-command-output"})
	if err != nil {
		t.Fatalf("byte stream chunks: %v", err)
	}
	if len(chunks) != 1 || !strings.Contains(chunks[0], "byte-command-output") {
		t.Fatalf("chunks = %#v", chunks)
	}
}

func TestIsCanonicalUUID(t *testing.T) {
	if !isCanonicalUUID("03d651b2-dd3e-4cb8-a0c1-e6e5afba046a") {
		t.Fatalf("valid UUID rejected")
	}
	for _, value := range []string{
		"",
		"03d651b2dd3e4cb8a0c1e6e5afba046a",
		"03d651b2-dd3e-4cb8-a0c1-e6e5afba046z",
		"03d651b2-dd3e-4cb8-a0c1-e6e5afba046a ",
		"03d651b2_dd3e_4cb8_a0c1_e6e5afba046a",
	} {
		if isCanonicalUUID(value) {
			t.Fatalf("invalid UUID accepted: %q", value)
		}
	}
}

func TestProbeByteStreamSourceLaneSendsSmokeFrames(t *testing.T) {
	const (
		streamID  = "03d651b2-dd3e-4cb8-a0c1-e6e5afba046a"
		routeID   = "9c77044a-934d-4381-a691-c7d7a2e86e07"
		channelID = "pipe_1"
		agentTok  = "agent-token"
		sourceTok = "source-token"
		sessionID = "source-session"
	)

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/bytes/source-sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("source session method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+agentTok {
			t.Fatalf("source session auth = %q", got)
		}

		var req byteStreamSourceSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode source session request: %v", err)
		}
		if req.ChannelID != channelID || req.StreamID != streamID || req.RouteID != routeID {
			t.Fatalf("source session request = %#v", req)
		}

		_ = json.NewEncoder(w).Encode(byteStreamSourceSessionResponse{
			StreamID:        streamID,
			RouteID:         routeID,
			SourceUserID:    "agent:" + channelID,
			SourceSessionID: sessionID,
			SourceToken:     sourceTok,
			ExpiresAt:       time.Now().Add(time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v2/bytes/stream", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+sourceTok {
			t.Fatalf("stream auth = %q", got)
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade stream: %v", err)
		}
		defer ws.Close()

		if err := ws.WriteJSON(byteStreamReadyFrame{
			Type:     "stream_ready",
			StreamID: streamID,
			Side:     "source",
			Paired:   true,
		}); err != nil {
			t.Fatalf("write ready: %v", err)
		}

		receivedChunks := make([]string, 0, 2)
		for i := uint64(0); i < 2; i++ {
			var chunk byteStreamFrame
			if err := ws.ReadJSON(&chunk); err != nil {
				t.Fatalf("read chunk %d: %v", i, err)
			}
			if chunk.Type != "chunk" || chunk.StreamID != streamID || chunk.SessionID != sessionID || chunk.ChunkIndex == nil || *chunk.ChunkIndex != i || chunk.Ciphertext == "" {
				t.Fatalf("chunk %d = %#v", i, chunk)
			}
			receivedChunks = append(receivedChunks, chunk.Ciphertext)
			if err := ws.WriteJSON(byteStreamFrame{
				Type:       "ack",
				StreamID:   streamID,
				SessionID:  "receiver-session",
				ChunkIndex: chunk.ChunkIndex,
			}); err != nil {
				t.Fatalf("write ack %d: %v", i, err)
			}
		}

		var done byteStreamFrame
		if err := ws.ReadJSON(&done); err != nil {
			t.Fatalf("read done: %v", err)
		}
		if done.Type != "done" || done.StreamID != streamID || done.SessionID != sessionID || done.ChunkIndex == nil || *done.ChunkIndex != 1 {
			t.Fatalf("done = %#v", done)
		}
		digest := sha256.New()
		for _, chunk := range receivedChunks {
			_, _ = digest.Write([]byte(chunk))
		}
		expectedDigest := fmt.Sprintf("%x", digest.Sum(nil))
		if done.DigestSHA256 != expectedDigest {
			t.Fatalf("done digest = %q, want %q", done.DigestSHA256, expectedDigest)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	oldServerAddr, oldToken := serverAddr, token
	serverAddr, token = parsed.Host, agentTok
	defer func() {
		serverAddr, token = oldServerAddr, oldToken
	}()

	ready, summary, err := probeByteStreamSourceLane(channelID, byteStreamRequestPayload{
		StreamID: streamID,
		RouteID:  routeID,
		Ts:       time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("probe source lane: %v", err)
	}
	if ready.Type != "stream_ready" || ready.StreamID != streamID || ready.Side != "source" || !ready.Paired {
		t.Fatalf("ready = %#v", ready)
	}
	if summary.Chunks != 2 || summary.Bytes == 0 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestProbeByteStreamSourceLaneDoesNotWriteWhenUnpaired(t *testing.T) {
	const (
		streamID  = "03d651b2-dd3e-4cb8-a0c1-e6e5afba046a"
		routeID   = "9c77044a-934d-4381-a691-c7d7a2e86e07"
		channelID = "pipe_1"
		agentTok  = "agent-token"
		sourceTok = "source-token"
		sessionID = "source-session"
	)

	chunkReceived := make(chan struct{}, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/bytes/source-sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(byteStreamSourceSessionResponse{
			StreamID:        streamID,
			RouteID:         routeID,
			SourceUserID:    "agent:" + channelID,
			SourceSessionID: sessionID,
			SourceToken:     sourceTok,
			ExpiresAt:       time.Now().Add(time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v2/bytes/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade stream: %v", err)
		}
		defer ws.Close()

		if err := ws.WriteJSON(byteStreamReadyFrame{
			Type:     "stream_ready",
			StreamID: streamID,
			Side:     "source",
			Paired:   false,
		}); err != nil {
			t.Fatalf("write ready: %v", err)
		}

		_ = ws.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		_, _, err = ws.ReadMessage()
		if err == nil {
			chunkReceived <- struct{}{}
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	oldServerAddr, oldToken := serverAddr, token
	serverAddr, token = parsed.Host, agentTok
	defer func() {
		serverAddr, token = oldServerAddr, oldToken
	}()

	ready, summary, err := probeByteStreamSourceLane(channelID, byteStreamRequestPayload{
		StreamID: streamID,
		RouteID:  routeID,
		Ts:       time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("probe source lane: %v", err)
	}
	if ready.Type != "stream_ready" || ready.StreamID != streamID || ready.Side != "source" || ready.Paired {
		t.Fatalf("ready = %#v", ready)
	}
	if summary.Chunks != 0 || summary.Bytes != 0 {
		t.Fatalf("summary = %#v", summary)
	}
	select {
	case <-chunkReceived:
		t.Fatal("agent wrote byte chunks before the source lane was paired")
	default:
	}
}

func TestProbeByteStreamSourceLaneRejectsAckWithoutSession(t *testing.T) {
	const (
		streamID  = "03d651b2-dd3e-4cb8-a0c1-e6e5afba046a"
		routeID   = "9c77044a-934d-4381-a691-c7d7a2e86e07"
		channelID = "pipe_1"
		agentTok  = "agent-token"
		sourceTok = "source-token"
		sessionID = "source-session"
	)

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/bytes/source-sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(byteStreamSourceSessionResponse{
			StreamID:        streamID,
			RouteID:         routeID,
			SourceUserID:    "agent:" + channelID,
			SourceSessionID: sessionID,
			SourceToken:     sourceTok,
			ExpiresAt:       time.Now().Add(time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v2/bytes/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade stream: %v", err)
		}
		defer ws.Close()

		if err := ws.WriteJSON(byteStreamReadyFrame{
			Type:     "stream_ready",
			StreamID: streamID,
			Side:     "source",
			Paired:   true,
		}); err != nil {
			t.Fatalf("write ready: %v", err)
		}

		var chunk byteStreamFrame
		if err := ws.ReadJSON(&chunk); err != nil {
			t.Fatalf("read chunk: %v", err)
		}
		if chunk.ChunkIndex == nil {
			t.Fatalf("chunk missing index: %#v", chunk)
		}
		if err := ws.WriteJSON(byteStreamFrame{
			Type:       "ack",
			StreamID:   streamID,
			ChunkIndex: chunk.ChunkIndex,
		}); err != nil {
			t.Fatalf("write malformed ack: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	oldServerAddr, oldToken := serverAddr, token
	serverAddr, token = parsed.Host, agentTok
	defer func() {
		serverAddr, token = oldServerAddr, oldToken
	}()

	_, _, err = probeByteStreamSourceLane(channelID, byteStreamRequestPayload{
		StreamID: streamID,
		RouteID:  routeID,
		Ts:       time.Now().UnixMilli(),
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected receiver ack frame") {
		t.Fatalf("probe source lane error = %v", err)
	}
}

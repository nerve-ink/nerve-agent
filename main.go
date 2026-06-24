package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

type Envelope struct {
	ID             string `json:"id"`
	ChannelID      string `json:"channel_id"`
	Text           string `json:"text"`
	Sender         string `json:"sender"`
	Severity       string `json:"severity"`
	Kind           string `json:"kind,omitempty"`
	Payload        string `json:"payload_raw"` // raw string preserved for Ed25519 verification
	Signature      string `json:"signature"`
	Pubkey         string `json:"pubkey"`
	ECDHPubkey     string `json:"ecdh_pubkey,omitempty"`
	EncryptionMode string `json:"encryption_mode,omitempty"`
}

type KeyringUpdate struct {
	Type string   `json:"type"`
	Keys []string `json:"keys"`
}

type byteStreamRequestPayload struct {
	StreamID string `json:"stream_id"`
	RouteID  string `json:"route_id"`
	Ts       int64  `json:"ts"`
}

type byteStreamSourceSessionRequest struct {
	ChannelID string `json:"channel_id"`
	StreamID  string `json:"stream_id"`
	RouteID   string `json:"route_id"`
}

type byteStreamSourceSessionResponse struct {
	StreamID        string `json:"stream_id"`
	RouteID         string `json:"route_id"`
	SourceUserID    string `json:"source_user_id"`
	SourceSessionID string `json:"source_session_id"`
	SourceToken     string `json:"source_token"`
	ExpiresAt       string `json:"expires_at"`
}

type byteStreamReadyFrame struct {
	Type     string `json:"type"`
	StreamID string `json:"stream_id"`
	Side     string `json:"side"`
	Paired   bool   `json:"paired"`
}

type byteStreamFrame struct {
	Type       string  `json:"type"`
	StreamID   string  `json:"stream_id"`
	SessionID  string  `json:"session_id"`
	ChunkIndex *uint64 `json:"chunk_index,omitempty"`
	Ciphertext string  `json:"ciphertext,omitempty"`
}

var (
	version             = "dev"
	serverAddr          string
	token               string
	handler             string
	keyFile             string
	cmdTimeout          time.Duration
	maxOutputBytes      int
	ecdhPrivKey         *ecdh.PrivateKey
	trustedKeys         = make(map[string]ed25519.PublicKey)
	symmetricChannelKey []byte
)

var (
	commandECDHSalt = []byte("nerve.command.ecdh.hkdf.salt.v1")
	commandECDHInfo = []byte("nerve.command.ecdh.aes-gcm.v1")
)

// limitedWriter caps the number of bytes written to buf.
type limitedWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		w.truncated = true
		return n, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	if _, err := w.buf.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}

func commandReplyOutput(output string, truncated bool, maxOutputBytes int, timedOut bool, timeout time.Duration, err error) string {
	if timedOut {
		output = fmt.Sprintf("[Error] Command timed out (%v limit).\n%s", timeout, output)
	}
	if truncated {
		output += fmt.Sprintf("\n[Output truncated at %dKB]", maxOutputBytes/1024)
	}
	if !timedOut && err != nil {
		output += fmt.Sprintf("\nError: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		return "[Command completed with no output]"
	}
	return output
}

func handlerReplyOutput(output string, truncated bool, maxOutputBytes int, timedOut bool, timeout time.Duration, err error) string {
	if timedOut {
		output = fmt.Sprintf("[Error] Handler timed out (%v limit).\n%s", timeout, output)
	}
	if truncated {
		output += fmt.Sprintf("\n[Output truncated at %dKB]", maxOutputBytes/1024)
	}
	if !timedOut && err != nil {
		output += fmt.Sprintf("\nError: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		return "[Handler completed with no output]"
	}
	return output
}

func runProcessWithTimeout(timeout time.Duration, maxOutputBytes int, stdin io.Reader, name string, args ...string) (string, bool, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	lw := &limitedWriter{limit: maxOutputBytes}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = lw
	cmd.Stderr = lw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 2 * time.Second

	err := cmd.Run()
	return lw.buf.String(), lw.truncated, ctx.Err() == context.DeadlineExceeded, err
}

func executionSeverity(timedOut bool, err error) string {
	if timedOut || err != nil {
		return "error"
	}
	return "info"
}

func main() {
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.StringVar(&serverAddr, "server", "localhost:8080", "Server address (host:port)")
	flag.StringVar(&token, "token", "", "Agent Token (AGENT_...)")
	flag.StringVar(&handler, "handler", "", "Path to custom script. If set, pipes all incoming JSON to stdin.")
	flag.StringVar(&keyFile, "key-file", "", "Path to ECDH key file (default: ~/.nerve/agent.key)")
	flag.DurationVar(&cmdTimeout, "timeout", 60*time.Second, "Max execution time per command")
	flag.IntVar(&maxOutputBytes, "max-output-bytes", 512*1024, "Max stdout/stderr bytes returned per command")
	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		return
	}

	if maxOutputBytes <= 0 {
		log.Fatal("max-output-bytes must be greater than zero")
	}

	if token == "" {
		log.Fatal("Token is required")
	}

	if keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Cannot determine home dir: %v", err)
		}
		keyFile = filepath.Join(home, ".nerve", "agent.key")
	}

	var err error
	ecdhPrivKey, err = loadOrGenerateECDHKey(keyFile)
	if err != nil {
		log.Fatalf("ECDH key error: %v", err)
	}

	scheme := "ws"
	if !strings.HasPrefix(serverAddr, "localhost") && !strings.HasPrefix(serverAddr, "127.") {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: serverAddr, Path: "/api/v1/stream"}

	// Log connection target without the token in the URL
	tokenPreview := token
	if len(tokenPreview) > 8 {
		tokenPreview = tokenPreview[:8] + "..."
	}
	log.Printf("Connecting to %s%s (token: %s)", u.Host, u.Path, tokenPreview)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	delay := 2 * time.Second
	for {
		connectAndListen(ctx, u.String())
		select {
		case <-ctx.Done():
			log.Println("Shutting down.")
			return
		default:
		}
		jitter := time.Duration(mathrand.Int63n(int64(delay / 2)))
		log.Printf("Disconnected. Retrying in %v...", delay+jitter)
		select {
		case <-time.After(delay + jitter):
		case <-ctx.Done():
			log.Println("Shutting down.")
			return
		}
		if delay < 64*time.Second {
			delay *= 2
		}
	}
}

func loadOrGenerateECDHKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := ecdh.X25519().NewPrivateKey(data)
		if err == nil {
			pubB64 := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
			log.Printf("🔑 Loaded ECDH key from %s (pub: %s...)", path, pubB64[:8])
			return key, nil
		}
	}

	// Generate new key
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(path, key.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("save ECDH key: %w", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	log.Printf("🔑 Generated new ECDH key, saved to %s (pub: %s...)", path, pubB64[:8])
	return key, nil
}

func connectAndListen(ctx context.Context, addr string) {
	headers := make(map[string][]string)
	headers["Authorization"] = []string{"Bearer " + token}

	c, resp, err := websocket.DefaultDialer.DialContext(ctx, addr, headers)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("Dial error: %s", formatDialError(err, resp))
		}
		return
	}
	defer c.Close()

	// Close WebSocket when context is cancelled (shutdown signal)
	go func() {
		<-ctx.Done()
		c.WriteMessage(websocket.CloseMessage, //nolint:errcheck
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "shutting down"))
		c.Close()
	}()

	log.Println("✅ Connected to Nerve Server")

	// Register ECDH pubkey with backend
	pubB64 := base64.StdEncoding.EncodeToString(ecdhPrivKey.PublicKey().Bytes())
	if writeErr := c.WriteJSON(map[string]string{"type": "register_pubkey", "pubkey": pubB64}); writeErr != nil {
		log.Printf("Failed to register pubkey: %v", writeErr)
	} else {
		log.Printf("🔑 Sent ECDH pubkey registration")
	}

	// iosECDHPubkey is cached per-connection from the first encrypted command received
	var iosECDHPubkey string

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		// Try parsing as Keyring Update
		var keyring KeyringUpdate
		if err := json.Unmarshal(message, &keyring); err == nil && keyring.Type == "keyring_update" {
			updateKeyring(keyring.Keys)
			continue
		}

		// Try parsing as Channel Key
		var chKey struct {
			Type string `json:"type"`
			Key  string `json:"key"`
		}
		if err := json.Unmarshal(message, &chKey); err == nil && chKey.Type == "channel_key" {
			if err := assimilateChannelKey(chKey.Key); err != nil {
				log.Printf("❌ Failed to assimilate channel key: %v", err)
			}
			continue
		}

		// Try parsing as Envelope
		var env Envelope
		if err := json.Unmarshal(message, &env); err != nil {
			log.Printf("JSON Error: %v", err)
			continue
		}

		// Cache iOS ECDH pubkey for encrypting replies
		if env.ECDHPubkey != "" {
			iosECDHPubkey = env.ECDHPubkey
		}

		if !shouldHandleEnvelope(env) {
			log.Printf("↩️ Ignoring non-command envelope kind=%q from %s", env.Kind, env.Sender)
			continue
		}

		handleMessage(c, env, iosECDHPubkey)
	}
}

func formatDialError(err error, resp *http.Response) string {
	if resp == nil {
		return err.Error()
	}

	body := ""
	if resp.Body != nil {
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if readErr == nil {
			body = strings.TrimSpace(string(data))
		}
	}
	if body == "" {
		body = resp.Status
	}
	return fmt.Sprintf("%v (%s: %s)", err, resp.Status, body)
}

func shouldHandleEnvelope(env Envelope) bool {
	return env.Kind == "command" || env.Kind == "byte_stream_request"
}

// updateKeyring replaces the trusted key list with keys from the backend.
//
// SECURITY NOTE (issue #23): This agent blindly trusts keyring_update messages
// received from the backend over the WebSocket connection. This is a known
// architectural limitation and zero-knowledge violation, but is accepted for
// the current phase of the project. In a fully zero-knowledge system, the agent
// would need to verify keyring updates through an out-of-band mechanism or
// cryptographic proof. For now, we assume the WebSocket connection to the backend
// is authenticated and trusted via the agent token.
func updateKeyring(keys []string) {
	trustedKeys = make(map[string]ed25519.PublicKey)
	count := 0
	for _, k := range keys {
		pkBytes, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(pkBytes) == 32 {
			trustedKeys[k] = ed25519.PublicKey(pkBytes)
			count++
		}
	}
	log.Printf("🔑 Updated Keyring: %d trusted keys", count)
}

func assimilateChannelKey(payload string) error {
	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid channel key payload format")
	}
	senderPubKey := parts[0]
	encryptedBox := parts[1]

	rawKeyBase64, err := decryptPayload(encryptedBox, senderPubKey)
	if err != nil {
		return fmt.Errorf("decrypt capsule: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(rawKeyBase64)
	if err != nil {
		return fmt.Errorf("decode raw key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("invalid channel key length: %d", len(key))
	}
	symmetricChannelKey = key
	log.Printf("🔑 Gracefully assimilated symmetric channel key")
	return nil
}

func decryptSymmetric(ciphertextB64 string, key []byte) (string, error) {
	combined, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(combined) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := combined[:12], combined[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return string(plaintext), nil
}

func encryptSymmetric(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func deriveSharedKey(peerECDHPubB64 string) ([]byte, error) {
	peerBytes, err := base64.StdEncoding.DecodeString(peerECDHPubB64)
	if err != nil {
		return nil, fmt.Errorf("decode peer pubkey: %w", err)
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer pubkey: %w", err)
	}
	sharedSecret, err := ecdhPrivKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	// Domain-separated HKDF-SHA256. Must match NerveCryptoManager.commandECDH*.
	h := hkdf.New(sha256.New, sharedSecret, commandECDHSalt, commandECDHInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return key, nil
}

func decryptPayload(ciphertextB64, senderECDHPubB64 string) (string, error) {
	aesKey, err := deriveSharedKey(senderECDHPubB64)
	if err != nil {
		return "", err
	}

	combined, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(combined) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := combined[:12], combined[12:]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt: %w", err)
	}
	return string(plaintext), nil
}

func encryptPayload(plaintext, recipientECDHPubB64 string) (string, error) {
	aesKey, err := deriveSharedKey(recipientECDHPubB64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func sendReply(conn *websocket.Conn, channelID, text, severity, iosECDHPubkey string) error {
	replyText := text
	encMode := ""

	if len(symmetricChannelKey) > 0 {
		encrypted, err := encryptSymmetric(text, symmetricChannelKey)
		if err != nil {
			log.Printf("⚠️  Reply symmetric encryption failed: %v — sending plaintext", err)
		} else {
			replyText = encrypted
			encMode = "e2e"
		}
	} else if iosECDHPubkey != "" {
		encrypted, err := encryptPayload(text, iosECDHPubkey)
		if err != nil {
			log.Printf("⚠️  Reply ECDH encryption failed: %v — sending plaintext", err)
		} else {
			replyText = encrypted
			encMode = "ecdh-aes-gcm"
		}
	}

	msg := Envelope{
		ChannelID:      channelID,
		Text:           replyText,
		Severity:       severity,
		Kind:           "agent_reply",
		EncryptionMode: encMode,
	}
	if encMode == "ecdh-aes-gcm" {
		msg.ECDHPubkey = base64.StdEncoding.EncodeToString(ecdhPrivKey.PublicKey().Bytes())
	}
	if err := conn.WriteJSON(msg); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}
	log.Printf("📤 Reply sent (mode=%s, plaintext_bytes=%d)", replyModeLabel(encMode), len(text))
	return nil
}

func replyModeLabel(encMode string) string {
	if encMode == "" {
		return "plaintext"
	}
	return encMode
}

func preview(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n]
}

func sendReplyLogged(conn *websocket.Conn, channelID, text, severity, iosECDHPubkey string) {
	if err := sendReply(conn, channelID, text, severity, iosECDHPubkey); err != nil {
		log.Printf("❌ Reply send failed: %v", err)
	}
}

func handleMessage(conn *websocket.Conn, env Envelope, iosECDHPubkey string) {
	log.Printf("📩 Received message from %s", env.Sender)

	// Verify Signature
	if env.Pubkey == "" || env.Signature == "" {
		sendReplyLogged(conn, env.ChannelID, "Error: Missing signature", "error", iosECDHPubkey)
		return
	}

	// Check if Pubkey is trusted
	pubKey, trusted := trustedKeys[env.Pubkey]
	if !trusted {
		sendReplyLogged(conn, env.ChannelID, fmt.Sprintf("Error: Untrusted Key %s...", preview(env.Pubkey, 8)), "error", iosECDHPubkey)
		return
	}

	// Decrypt payload if E2E encrypted
	payloadToVerify := env.Payload
	if env.EncryptionMode == "e2e" {
		if len(symmetricChannelKey) == 0 {
			log.Printf("❌ Symmetric channel key not assimilated yet")
			sendReplyLogged(conn, env.ChannelID, "Error: Symmetric channel key missing", "error", iosECDHPubkey)
			return
		}
		decrypted, err := decryptSymmetric(env.Payload, symmetricChannelKey)
		if err != nil {
			log.Printf("❌ Decryption failed: %v", err)
			sendReplyLogged(conn, env.ChannelID, "Error: Decryption failed", "error", iosECDHPubkey)
			return
		}
		payloadToVerify = decrypted
		log.Printf("🔓 Payload decrypted successfully using symmetric channel key")
	} else if env.ECDHPubkey != "" {
		decrypted, err := decryptPayload(env.Payload, env.ECDHPubkey)
		if err != nil {
			log.Printf("❌ Decryption failed: %v", err)
			sendReplyLogged(conn, env.ChannelID, "Error: Decryption failed", "error", iosECDHPubkey)
			return
		}
		payloadToVerify = decrypted
		log.Printf("🔓 Payload decrypted successfully using ECDH")
	}

	// Verify Ed25519 signature on plaintext payload
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		log.Printf("Invalid signature encoding: %v", err)
		sendReplyLogged(conn, env.ChannelID, "Error: Invalid Signature", "error", iosECDHPubkey)
		return
	}
	if !ed25519.Verify(pubKey, []byte(payloadToVerify), sigBytes) {
		sendReplyLogged(conn, env.ChannelID, "Error: Invalid Signature", "error", iosECDHPubkey)
		return
	}

	if env.Kind == "byte_stream_request" {
		handleByteStreamRequest(conn, env, payloadToVerify, iosECDHPubkey)
		return
	}

	// Dispatch to handler if set
	if handler != "" {
		log.Printf("🚀 Dispatching to handler: %s", handler)

		// Parse handler arguments (issue #34)
		parts := strings.Fields(handler)
		if len(parts) == 0 {
			sendReplyLogged(conn, env.ChannelID, "Error: handler flag is empty", "error", iosECDHPubkey)
			return
		}

		// Pass decrypted envelope as JSON to handler stdin
		handlerEnv := env
		handlerEnv.Payload = payloadToVerify
		envJSON, err := json.Marshal(handlerEnv)
		if err != nil {
			sendReplyLogged(conn, env.ChannelID, fmt.Sprintf("Error: marshal handler env: %v", err), "error", iosECDHPubkey)
			return
		}

		output, truncated, timedOut, err := runProcessWithTimeout(cmdTimeout, maxOutputBytes, bytes.NewReader(envJSON), parts[0], parts[1:]...)
		if timedOut {
			log.Printf("⏱️ Handler timed out after %v; killed process group", cmdTimeout)
		}
		output = handlerReplyOutput(output, truncated, maxOutputBytes, timedOut, cmdTimeout, err)
		sendReplyLogged(conn, env.ChannelID, output, executionSeverity(timedOut, err), iosECDHPubkey)
		return
	}

	// Parse command payload
	var cmdObj struct {
		Cmd string `json:"cmd"`
		Ts  int64  `json:"ts"`
	}
	if err := json.Unmarshal([]byte(payloadToVerify), &cmdObj); err != nil {
		sendReplyLogged(conn, env.ChannelID, "Error: Invalid Payload JSON", "error", iosECDHPubkey)
		return
	}

	// Replay Protection: reject commands older than 30s or more than 10s in the future
	age := time.Since(time.UnixMilli(cmdObj.Ts))
	if age > 30*time.Second || age < -10*time.Second {
		sendReplyLogged(conn, env.ChannelID, "Error: Command Expired (Replay Protection)", "error", iosECDHPubkey)
		return
	}

	// Execute Shell with configurable timeout
	realCmd := cmdObj.Cmd
	log.Printf("Executing: %s", realCmd)

	output, truncated, timedOut, err := runProcessWithTimeout(cmdTimeout, maxOutputBytes, nil, "sh", "-c", realCmd)

	if timedOut {
		log.Printf("⏱️ Command timed out after %v; killed process group (stdout_stderr_bytes=%d, err=%v)", cmdTimeout, len(output), err)
	} else {
		log.Printf("✅ Command finished (stdout_stderr_bytes=%d, err=%v)", len(output), err)
	}
	output = commandReplyOutput(output, truncated, maxOutputBytes, timedOut, cmdTimeout, err)
	sendReplyLogged(conn, env.ChannelID, output, executionSeverity(timedOut, err), iosECDHPubkey)
}

func handleByteStreamRequest(conn *websocket.Conn, env Envelope, payloadToVerify, iosECDHPubkey string) {
	var req byteStreamRequestPayload
	if err := json.Unmarshal([]byte(payloadToVerify), &req); err != nil {
		sendReplyLogged(conn, env.ChannelID, "Error: Invalid byte stream request", "error", iosECDHPubkey)
		return
	}
	if err := validateByteStreamRequest(req, time.Now()); err != nil {
		sendReplyLogged(conn, env.ChannelID, fmt.Sprintf("Error: %v", err), "error", iosECDHPubkey)
		return
	}

	log.Printf("🧵 Byte stream source probe requested stream=%s route=%s", req.StreamID, preview(req.RouteID, 8))
	ready, err := probeByteStreamSourceLane(env.ChannelID, req.StreamID, req.RouteID)
	if err != nil {
		sendReplyLogged(conn, env.ChannelID, fmt.Sprintf("Byte stream source failed: %v", err), "error", iosECDHPubkey)
		return
	}

	status := "waiting"
	if ready.Paired {
		status = "paired"
	}
	sendReplyLogged(conn, env.ChannelID, fmt.Sprintf("Byte stream source lane %s; smoke frame sent: %s", status, preview(req.RouteID, 8)), "standard", iosECDHPubkey)
}

func validateByteStreamRequest(req byteStreamRequestPayload, now time.Time) error {
	age := now.Sub(time.UnixMilli(req.Ts))
	if age > 30*time.Second || age < -10*time.Second {
		return fmt.Errorf("Byte stream request expired")
	}
	if !isCanonicalUUID(req.StreamID) || !isCanonicalUUID(req.RouteID) {
		return fmt.Errorf("Byte stream route missing")
	}
	return nil
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func probeByteStreamSourceLane(channelID, streamID, routeID string) (byteStreamReadyFrame, error) {
	session, err := createByteStreamSourceSession(channelID, streamID, routeID)
	if err != nil {
		return byteStreamReadyFrame{}, err
	}

	u := url.URL{Scheme: websocketSchemeForServer(serverAddr), Host: serverAddr, Path: "/api/v2/bytes/stream"}
	headers := http.Header{"Authorization": []string{"Bearer " + session.SourceToken}}
	c, resp, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return byteStreamReadyFrame{}, fmt.Errorf("open source lane: %s", formatDialError(err, resp))
	}
	defer c.Close()

	_, raw, err := c.ReadMessage()
	if err != nil {
		return byteStreamReadyFrame{}, fmt.Errorf("read source ready: %w", err)
	}

	var ready byteStreamReadyFrame
	if err := json.Unmarshal(raw, &ready); err != nil {
		return byteStreamReadyFrame{}, fmt.Errorf("decode source ready: %w", err)
	}
	if ready.Type != "stream_ready" || ready.StreamID != streamID || ready.Side != "source" {
		return byteStreamReadyFrame{}, fmt.Errorf("unexpected source ready frame")
	}
	if !ready.Paired {
		return ready, nil
	}
	if err := writeByteStreamSmokeFrames(c, session); err != nil {
		return byteStreamReadyFrame{}, err
	}
	return ready, nil
}

func writeByteStreamSmokeFrames(c *websocket.Conn, session byteStreamSourceSessionResponse) error {
	chunks := []string{
		"agent-smoke-byte-frame-0",
		"agent-smoke-byte-frame-1",
	}
	var lastChunkIndex uint64
	for i, ciphertext := range chunks {
		chunkIndex := uint64(i)
		lastChunkIndex = chunkIndex
		chunk := byteStreamFrame{
			Type:       "chunk",
			StreamID:   session.StreamID,
			SessionID:  session.SourceSessionID,
			ChunkIndex: &chunkIndex,
			Ciphertext: ciphertext,
		}
		if err := c.WriteJSON(chunk); err != nil {
			return fmt.Errorf("write source chunk %d: %w", chunkIndex, err)
		}

		if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return fmt.Errorf("set ack read deadline: %w", err)
		}
		_, raw, err := c.ReadMessage()
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			return fmt.Errorf("read receiver ack %d: %w", chunkIndex, err)
		}

		var ack byteStreamFrame
		if err := json.Unmarshal(raw, &ack); err != nil {
			return fmt.Errorf("decode receiver ack %d: %w", chunkIndex, err)
		}
		if ack.Type != "ack" || ack.StreamID != session.StreamID || ack.ChunkIndex == nil || *ack.ChunkIndex != chunkIndex {
			return fmt.Errorf("unexpected receiver ack frame for chunk %d", chunkIndex)
		}
		log.Printf("🧵 Byte stream ack received stream=%s chunk=%d", session.StreamID, chunkIndex)
	}

	done := byteStreamFrame{
		Type:       "done",
		StreamID:   session.StreamID,
		SessionID:  session.SourceSessionID,
		ChunkIndex: &lastChunkIndex,
	}
	if err := c.WriteJSON(done); err != nil {
		return fmt.Errorf("write source done: %w", err)
	}

	return nil
}

func createByteStreamSourceSession(channelID, streamID, routeID string) (byteStreamSourceSessionResponse, error) {
	endpoint := url.URL{Scheme: httpSchemeForServer(serverAddr), Host: serverAddr, Path: "/api/v2/bytes/source-sessions"}
	body, err := json.Marshal(byteStreamSourceSessionRequest{
		ChannelID: channelID,
		StreamID:  streamID,
		RouteID:   routeID,
	})
	if err != nil {
		return byteStreamSourceSessionResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return byteStreamSourceSessionResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return byteStreamSourceSessionResponse{}, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return byteStreamSourceSessionResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return byteStreamSourceSessionResponse{}, fmt.Errorf("source session HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out byteStreamSourceSessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return byteStreamSourceSessionResponse{}, err
	}
	if out.SourceToken == "" {
		return byteStreamSourceSessionResponse{}, fmt.Errorf("source session token missing")
	}
	return out, nil
}

func httpSchemeForServer(addr string) string {
	if strings.HasPrefix(addr, "localhost") || strings.HasPrefix(addr, "127.") {
		return "http"
	}
	return "https"
}

func websocketSchemeForServer(addr string) string {
	if strings.HasPrefix(addr, "localhost") || strings.HasPrefix(addr, "127.") {
		return "ws"
	}
	return "wss"
}

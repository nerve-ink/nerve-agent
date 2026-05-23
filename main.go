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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

type Envelope struct {
	ID         string `json:"id"`
	ChannelID  string `json:"channel_id"`
	Text       string `json:"text"`
	Sender     string `json:"sender"`
	Severity   string `json:"severity"`
	Payload    string `json:"payload_raw"` // raw string preserved for Ed25519 verification
	Signature  string `json:"signature"`
	Pubkey     string `json:"pubkey"`
	ECDHPubkey string `json:"ecdh_pubkey,omitempty"`
}

type KeyringUpdate struct {
	Type string   `json:"type"`
	Keys []string `json:"keys"`
}

var (
	serverAddr  string
	token       string
	handler     string
	keyFile     string
	ecdhPrivKey *ecdh.PrivateKey
	trustedKeys = make(map[string]ed25519.PublicKey)
)

func main() {
	flag.StringVar(&serverAddr, "server", "localhost:8080", "Server address (host:port)")
	flag.StringVar(&token, "token", "", "Agent Token (AGENT_...)")
	flag.StringVar(&handler, "handler", "", "Path to custom script. If set, pipes all incoming JSON to stdin.")
	flag.StringVar(&keyFile, "key-file", "", "Path to ECDH key file (default: ~/.nerve/agent.key)")
	flag.Parse()

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
	u := url.URL{Scheme: scheme, Host: serverAddr, Path: "/api/v1/stream", RawQuery: "token=" + token}
	log.Printf("Connecting to %s", u.String())

	for {
		connectAndListen(u.String())
		log.Println("Disconnected. Retrying in 5s...")
		time.Sleep(5 * time.Second)
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

func connectAndListen(addr string) {
	c, _, err := websocket.DefaultDialer.Dial(addr, nil)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer c.Close()

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

		handleMessage(c, env, iosECDHPubkey)
	}
}

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
	// HKDF-SHA256 with empty salt and info — matches Swift hkdfDerivedSymmetricKey
	h := hkdf.New(sha256.New, sharedSecret, []byte{}, []byte{})
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

func sendReply(conn *websocket.Conn, channelID, text, severity, iosECDHPubkey string) {
	replyText := text
	ecdhPubkey := ""

	if iosECDHPubkey != "" {
		encrypted, err := encryptPayload(text, iosECDHPubkey)
		if err != nil {
			log.Printf("⚠️  Reply encryption failed: %v — sending plaintext", err)
		} else {
			replyText = encrypted
			ecdhPubkey = base64.StdEncoding.EncodeToString(ecdhPrivKey.PublicKey().Bytes())
		}
	}

	msg := Envelope{
		ChannelID:  channelID,
		Text:       replyText,
		Severity:   severity,
		ECDHPubkey: ecdhPubkey,
	}
	conn.WriteJSON(msg) //nolint:errcheck
}

func handleMessage(conn *websocket.Conn, env Envelope, iosECDHPubkey string) {
	log.Printf("📩 Received message from %s", env.Sender)

	// Verify Signature
	if env.Pubkey == "" || env.Signature == "" {
		sendReply(conn, env.ChannelID, "Error: Missing signature", "error", iosECDHPubkey)
		return
	}

	// Check if Pubkey is trusted
	pubKey, trusted := trustedKeys[env.Pubkey]
	if !trusted {
		sendReply(conn, env.ChannelID, fmt.Sprintf("Error: Untrusted Key %s...", env.Pubkey[:8]), "error", iosECDHPubkey)
		return
	}

	// Decrypt payload if E2E encrypted
	payloadToVerify := env.Payload
	if env.ECDHPubkey != "" {
		decrypted, err := decryptPayload(env.Payload, env.ECDHPubkey)
		if err != nil {
			log.Printf("❌ Decryption failed: %v", err)
			sendReply(conn, env.ChannelID, "Error: Decryption failed", "error", iosECDHPubkey)
			return
		}
		payloadToVerify = decrypted
		log.Printf("🔓 Payload decrypted successfully")
	}

	// Verify Ed25519 signature on plaintext payload
	sigBytes, _ := base64.StdEncoding.DecodeString(env.Signature)
	if !ed25519.Verify(pubKey, []byte(payloadToVerify), sigBytes) {
		sendReply(conn, env.ChannelID, "Error: Invalid Signature", "error", iosECDHPubkey)
		return
	}

	// Dispatch to handler if set
	if handler != "" {
		log.Printf("🚀 Dispatching to handler: %s", handler)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, handler)
		// Pass decrypted envelope as JSON to handler stdin
		handlerEnv := env
		handlerEnv.Payload = payloadToVerify
		envJSON, _ := json.Marshal(handlerEnv)
		cmd.Stdin = bytes.NewReader(envJSON)

		out, err := cmd.CombinedOutput()
		output := string(out)

		if ctx.Err() == context.DeadlineExceeded {
			output += "\n[Error] Handler timed out (30s limit)."
		} else if err != nil {
			output += fmt.Sprintf("\nError: %v", err)
		}

		if strings.TrimSpace(output) != "" {
			sendReply(conn, env.ChannelID, output, "info", iosECDHPubkey)
		}
		return
	}

	// Parse command payload
	var cmdObj struct {
		Cmd string `json:"cmd"`
		Ts  int64  `json:"ts"`
	}
	if err := json.Unmarshal([]byte(payloadToVerify), &cmdObj); err != nil {
		sendReply(conn, env.ChannelID, "Error: Invalid Payload JSON", "error", iosECDHPubkey)
		return
	}

	// Replay Protection (30s window)
	if time.Since(time.UnixMilli(cmdObj.Ts)) > 30*time.Second {
		sendReply(conn, env.ChannelID, "Error: Command Expired (Replay Protection)", "error", iosECDHPubkey)
		return
	}

	// Execute Shell with Timeout
	realCmd := cmdObj.Cmd
	log.Printf("🚀 Executing: %s", realCmd)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", realCmd)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if ctx.Err() == context.DeadlineExceeded {
		output += "\n[Error] Command timed out (5s limit)."
	} else if err != nil {
		output += fmt.Sprintf("\nError: %v", err)
	}

	sendReply(conn, env.ChannelID, output, "info", iosECDHPubkey)
}

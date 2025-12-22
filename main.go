package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Envelope struct {
	ID        string `json:"id"`
	ChannelID string `json:"channel_id"`
	Text      string `json:"text"`
	Sender    string `json:"sender"`
	Severity  string `json:"severity"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Pubkey    string `json:"pubkey"`
}

type KeyringUpdate struct {
	Type string   `json:"type"`
	Keys []string `json:"keys"`
}

var (
	serverAddr string
	token      string
	trustedKeys = make(map[string]ed25519.PublicKey)
)

func main() {
	flag.StringVar(&serverAddr, "server", "localhost:8080", "Server address (host:port)")
	flag.StringVar(&token, "token", "", "Agent Token (AGENT_...")
	flag.Parse()

	if token == "" {
		log.Fatal("Token is required")
	}

	u := url.URL{Scheme: "ws", Host: serverAddr, Path: "/api/v1/stream", RawQuery: "token=" + token}
	log.Printf("Connecting to %s", u.String())

	for {
		connectAndListen(u.String())
		log.Println("Disconnected. Retrying in 5s...")
		time.Sleep(5 * time.Second)
	}
}

func connectAndListen(addr string) {
	c, _, err := websocket.DefaultDialer.Dial(addr, nil)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer c.Close()

	log.Println("✅ Connected to Nerve Server")

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		// LOG EVERYTHING for debugging
		log.Printf("DEBUG: Received msg: %s", string(message))

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

		handleMessage(c, env)
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

func handleMessage(conn *websocket.Conn, env Envelope) {
	// Only process commands
	if !strings.HasPrefix(env.Text, "CMD: ") {
		return
	}

	log.Printf("📩 Received Command from %s", env.Sender)

	// Verify Signature
	if env.Pubkey == "" || env.Signature == "" {
		sendReply(conn, env.ChannelID, "Error: Missing signature", "error")
		return
	}

	// Check if Pubkey is trusted
	pubKey, trusted := trustedKeys[env.Pubkey]
	if !trusted {
		sendReply(conn, env.ChannelID, fmt.Sprintf("Error: Untrusted Key %s...", env.Pubkey[:8]), "error")
		return
	}

	sigBytes, _ := base64.StdEncoding.DecodeString(env.Signature)
	if !ed25519.Verify(pubKey, []byte(env.Payload), sigBytes) {
		sendReply(conn, env.ChannelID, "Error: Invalid Signature", "error")
		return
	}

	// Execute
	
	var cmdObj struct {
		Cmd string `json:"cmd"`
		Ts  int64  `json:"ts"`
	}
	if err := json.Unmarshal([]byte(env.Payload), &cmdObj); err != nil {
		sendReply(conn, env.ChannelID, "Error: Invalid Payload JSON", "error")
		return
	}

	// Replay Protection (basic)
	if time.Since(time.UnixMilli(cmdObj.Ts)) > 30*time.Second {
		sendReply(conn, env.ChannelID, "Error: Command Expired (Replay Protection)", "error")
		return
	}

	// Execute Shell with Timeout
	realCmd := strings.TrimPrefix(cmdObj.Cmd, "/cmd ")
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

	sendReply(conn, env.ChannelID, output, "info")
}

func sendReply(conn *websocket.Conn, channelID, text, severity string) {
	msg := Envelope{
		ChannelID: channelID,
		Text:      text,
		Severity:  severity,
	}
	conn.WriteJSON(msg)
}
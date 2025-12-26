// server/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/InetByOu/whisper/common"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	listenAddr = flag.String("listen", ":4556", "UDP listen address")
	psk        = flag.String("psk", "", "Pre-shared key (32 bytes)")
)

type Session struct {
	aead       chacha20poly1305.AEAD
	lastSeq    uint64
	clientAddr *net.UDPAddr
	lastSeen   time.Time
	sessionID  []byte
}

var sessions = make(map[string]*Session)

func main() {
	flag.Parse()
	if len(*psk) != chacha20poly1305.KeySize {
		log.Fatal("PSK must be exactly 32 bytes")
	}

	aead, _ := chacha20poly1305.NewX([]byte(*psk))

	udpAddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Printf("whisper server listening on %s", *listenAddr)

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		go handleClient(conn, clientAddr, data, aead)
	}
}

func handleClient(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, serverAEAD chacha20poly1305.AEAD) {
	_, seqBytes, encrypted := common.ExtractPayload(data)
	if encrypted == nil {
		return
	}

	key := clientAddr.String()
	session, exists := sessions[key]

	if !exists || time.Since(session.lastSeen) > 5*time.Minute {
		// New session - use server key for first packet
		session = &Session{
			aead:       serverAEAD,
			clientAddr: clientAddr,
			lastSeen:   time.Now(),
			sessionID:  common.GenerateSessionID(),
		}
		sessions[key] = session
	}

	seq := common.BytesToUint64(seqBytes)
	if seq <= session.lastSeq {
		return // replay or out of order
	}
	session.lastSeq = seq
	session.lastSeen = time.Now()

	nonce := make([]byte, common.NonceSize)
	copy(nonce, encrypted[:common.NonceSize])
	ciphertext := encrypted[common.NonceSize:]

	plaintext, err := session.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Remove padding
	for i := len(plaintext) - 1; i >= 0; i-- {
		if plaintext[i] != 0 {
			plaintext = plaintext[:i+1]
			break
		}
	}

	if len(plaintext) == 0 {
		return
	}

	// Very simple SOCKS5-like request (only CONNECT for now)
	if len(plaintext) < 8 || plaintext[0] != 0x01 {
		return
	}

	// Forward to destination
	destConn, err := net.DialTimeout("tcp", fmt.Sprintf("%d.%d.%d.%d:%d",
		plaintext[4], plaintext[5], plaintext[6], plaintext[7],
		binary.BigEndian.Uint16(plaintext[2:4])), 10*time.Second)
	if err != nil {
		return
	}
	defer destConn.Close()

	_, err = destConn.Write(plaintext[8:])
	if err != nil {
		return
	}

	response := make([]byte, 65535)
	n, err := destConn.Read(response)
	if err != nil && n == 0 {
		return
	}

	// Encrypt response
	respNonce := common.GenerateNonce()
	aead := session.aead
	cipherResp := aead.Seal(nil, respNonce, response[:n], nil)

	packet := common.BuildStealthPacket(session.sessionID, common.Uint64ToBytes(seq+1), append(respNonce, cipherResp...))

	conn.WriteToUDP(packet, clientAddr)
}

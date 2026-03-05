// Package crypto provides post-quantum cryptographic primitives for
// CyberShield-X: CRYSTALS-Kyber-1024 key encapsulation, hybrid
// X25519+Kyber key exchange, and CRYSTALS-Dilithium3 signatures.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// ──────────────────────────────────────────────
// CRYSTALS-Kyber-1024 Key Encapsulation
// ──────────────────────────────────────────────

// KyberKeyPair holds a Kyber-1024 key pair.
type KyberKeyPair struct {
	PublicKey  *kyber1024.PublicKey
	PrivateKey *kyber1024.PrivateKey
}

// GenerateKyberKeyPair generates a new CRYSTALS-Kyber-1024 keypair.
func GenerateKyberKeyPair() (*KyberKeyPair, error) {
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("kyber keygen: %w", err)
	}
	return &KyberKeyPair{PublicKey: pk, PrivateKey: sk}, nil
}

// KyberEncapsulate produces a shared secret and ciphertext for the recipient.
func KyberEncapsulate(pk *kyber1024.PublicKey) (ciphertext, sharedSecret []byte, err error) {
	ct, ss, err := kyber1024.Encapsulate(rand.Reader, pk)
	if err != nil {
		return nil, nil, fmt.Errorf("kyber encaps: %w", err)
	}
	return ct, ss, nil
}

// KyberDecapsulate recovers the shared secret from a ciphertext.
func KyberDecapsulate(sk *kyber1024.PrivateKey, ciphertext []byte) ([]byte, error) {
	ss, err := kyber1024.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kyber decaps: %w", err)
	}
	return ss, nil
}

// ──────────────────────────────────────────────
// Hybrid X25519 + Kyber-1024 Key Exchange
// ──────────────────────────────────────────────

// HybridKeyExchange contains both classical and PQC keying material.
type HybridKeyExchange struct {
	X25519Private *ecdh.PrivateKey
	X25519Public  *ecdh.PublicKey
	Kyber         *KyberKeyPair
}

// NewHybridKeyExchange generates fresh X25519 and Kyber-1024 key pairs.
func NewHybridKeyExchange() (*HybridKeyExchange, error) {
	curve := ecdh.X25519()
	xPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		return nil, err
	}
	return &HybridKeyExchange{
		X25519Private: xPriv,
		X25519Public:  xPriv.PublicKey(),
		Kyber:         kp,
	}, nil
}

// HybridSharedSecret combines X25519 and Kyber shared secrets via XOR.
func HybridSharedSecret(x25519Secret, kyberSecret []byte) []byte {
	minLen := len(x25519Secret)
	if len(kyberSecret) < minLen {
		minLen = len(kyberSecret)
	}
	combined := make([]byte, 32)
	for i := 0; i < 32 && i < minLen; i++ {
		combined[i] = x25519Secret[i] ^ kyberSecret[i]
	}
	return combined
}

// ──────────────────────────────────────────────
// CRYSTALS-Dilithium3 Signatures
// ──────────────────────────────────────────────

// DilithiumKeyPair holds a Dilithium mode3 key pair.
type DilithiumKeyPair struct {
	PublicKey  *mode3.PublicKey
	PrivateKey *mode3.PrivateKey
}

// GenerateDilithiumKeyPair creates a fresh Dilithium3 signing keypair.
func GenerateDilithiumKeyPair() (*DilithiumKeyPair, error) {
	pk, sk, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("dilithium keygen: %w", err)
	}
	return &DilithiumKeyPair{PublicKey: pk, PrivateKey: sk}, nil
}

// DilithiumSign signs a message with Dilithium3.
func DilithiumSign(sk *mode3.PrivateKey, message []byte) []byte {
	return mode3.Sign(sk, message)
}

// DilithiumVerify verifies a Dilithium3 signature.
func DilithiumVerify(pk *mode3.PublicKey, message, signature []byte) bool {
	return mode3.Verify(pk, message, signature)
}

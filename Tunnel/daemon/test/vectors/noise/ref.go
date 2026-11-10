// A second implementation of ts2021's handshake and records, written from the Noise specification
// (revision 34: sections 4 and 5, the IK pattern of section 7.5) and the message layouts in
// controlbase/messages.go - not from controlbase's code - so the vectors do not rest on one
// implementation alone. kat_test.go checks it against controlbase byte for byte before it writes a
// single vector, then uses it for what controlbase cannot be made to produce: an empty record and
// records at far counters.
//
// Primitives: X25519 from crypto/ecdh, HKDF written out over crypto/hmac and BLAKE2s (not
// x/crypto/hkdf, which controlbase uses), ChaCha20-Poly1305 from x/crypto.

package main

import (
	"crypto/ecdh"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	refProtocolName   = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	refProloguePrefix = "Tailscale Control Protocol v"

	refInitLen        = 101
	refRespLen        = 51
	refMaxPlaintext   = 4096 - 3 - 16 // one record: 4096 bytes on the wire with header and tag
	refMsgInitiation  = 1
	refMsgResponse    = 2
	refMsgRecord      = 4
	refInitPayloadLen = 96
	refRespPayloadLen = 48
)

type key32 = [32]byte

func newBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func refHMAC(k, data []byte) []byte {
	m := hmac.New(newBLAKE2s, k)
	m.Write(data)
	return m.Sum(nil)
}

// refHKDF2 is Noise's HKDF(chaining_key, input_key_material) with two outputs (section 4.3).
func refHKDF2(ck key32, ikm []byte) (out1, out2 key32) {
	temp := refHMAC(ck[:], ikm)
	copy(out1[:], refHMAC(temp, []byte{0x01}))
	copy(out2[:], refHMAC(temp, append(out1[:], 0x02)))
	return out1, out2
}

func refClamp(seed key32) key32 {
	seed[0] &= 248
	seed[31] = (seed[31] & 127) | 64
	return seed
}

func refPublic(priv key32) key32 {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		panic(err)
	}
	var out key32
	copy(out[:], k.PublicKey().Bytes())
	return out
}

// refDH refuses an all-zero result, as x/crypto/curve25519.X25519 does inside controlbase.
func refDH(priv, pub key32) (key32, error) {
	var out key32
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return out, err
	}
	p, err := ecdh.X25519().NewPublicKey(pub[:])
	if err != nil {
		return out, err
	}
	s, err := k.ECDH(p)
	if err != nil {
		return out, err
	}
	copy(out[:], s)
	return out, nil
}

// refSymmetric is Noise's SymmetricState (section 5.2). Every key it hands out is used for one
// AEAD only, so the CipherState nonce is always 0 and is not kept.
type refSymmetric struct {
	h, ck key32
}

func newRefSymmetric(version uint16, responderStatic key32) *refSymmetric {
	s := &refSymmetric{}
	s.h = blake2s.Sum256([]byte(refProtocolName)) // 33 bytes, more than HASHLEN: hashed
	s.ck = s.h
	s.mixHash([]byte(refProloguePrefix + strconv.FormatUint(uint64(version), 10)))
	s.mixHash(responderStatic[:]) // IK's pre-message: <- s
	return s
}

func (s *refSymmetric) mixHash(data []byte) {
	d := newBLAKE2s()
	d.Write(s.h[:])
	d.Write(data)
	d.Sum(s.h[:0])
}

func (s *refSymmetric) mixKey(dh key32) (k key32) {
	s.ck, k = refHKDF2(s.ck, dh[:])
	return k
}

func (s *refSymmetric) encryptAndHash(k key32, pt []byte) []byte {
	a, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}
	ct := a.Seal(nil, make([]byte, chacha20poly1305.NonceSize), pt, s.h[:])
	s.mixHash(ct)
	return ct
}

func (s *refSymmetric) decryptAndHash(k key32, ct []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}
	pt, err := a.Open(nil, make([]byte, chacha20poly1305.NonceSize), ct, s.h[:])
	if err != nil {
		return nil, err
	}
	s.mixHash(ct)
	return pt, nil
}

// split returns (initiator -> responder, responder -> initiator).
func (s *refSymmetric) split() (key32, key32) {
	return refHKDF2(s.ck, nil)
}

// refClient is the initiator between its two messages.
type refClient struct {
	sym       *refSymmetric
	machine   key32 // static private
	ephemeral key32 // private
}

// refInitiation writes -> e, es, s, ss. ephSeed is the 32 random bytes; stored clamped, as
// key.NewMachine does (X25519 clamps anyway).
func refInitiation(machine, controlPub, ephSeed key32, version uint16) (msg [refInitLen]byte, c *refClient, err error) {
	c = &refClient{sym: newRefSymmetric(version, controlPub), machine: machine, ephemeral: refClamp(ephSeed)}
	binary.BigEndian.PutUint16(msg[0:2], version)
	msg[2] = refMsgInitiation
	binary.BigEndian.PutUint16(msg[3:5], refInitPayloadLen)

	ePub := refPublic(c.ephemeral)
	copy(msg[5:37], ePub[:])
	c.sym.mixHash(ePub[:]) // e: no MixKey, that is psk mode only

	es, err := refDH(c.ephemeral, controlPub)
	if err != nil {
		return msg, nil, fmt.Errorf("es: %w", err)
	}
	k := c.sym.mixKey(es)
	mPub := refPublic(machine)
	copy(msg[37:85], c.sym.encryptAndHash(k, mPub[:])) // s

	ss, err := refDH(machine, controlPub)
	if err != nil {
		return msg, nil, fmt.Errorf("ss: %w", err)
	}
	k = c.sym.mixKey(ss)
	copy(msg[85:101], c.sym.encryptAndHash(k, nil)) // empty payload
	return msg, c, nil
}

// consume reads <- e, ee, se and splits: (tx, rx, handshake hash).
func (c *refClient) consume(resp [refRespLen]byte) (tx, rx, h key32, err error) {
	if resp[0] != refMsgResponse || binary.BigEndian.Uint16(resp[1:3]) != refRespPayloadLen {
		return tx, rx, h, errors.New("not a response")
	}
	var re key32
	copy(re[:], resp[3:35])
	c.sym.mixHash(re[:])
	ee, err := refDH(c.ephemeral, re)
	if err != nil {
		return tx, rx, h, fmt.Errorf("ee: %w", err)
	}
	c.sym.mixKey(ee)
	se, err := refDH(c.machine, re)
	if err != nil {
		return tx, rx, h, fmt.Errorf("se: %w", err)
	}
	k := c.sym.mixKey(se)
	if _, err := c.sym.decryptAndHash(k, resp[35:51]); err != nil {
		return tx, rx, h, fmt.Errorf("response tag: %w", err)
	}
	tx, rx = c.sym.split()
	return tx, rx, c.sym.h, nil
}

// refResponse is the server's side of a whole handshake.
type refResponse struct {
	msg        [refRespLen]byte
	machinePub key32 // who the initiation came from
	version    uint16
	c2s, s2c   key32
	hash       key32
}

func refRespond(controlPriv key32, init [refInitLen]byte, ephSeed key32) (*refResponse, error) {
	if init[2] != refMsgInitiation || binary.BigEndian.Uint16(init[3:5]) != refInitPayloadLen {
		return nil, errors.New("not an initiation")
	}
	r := &refResponse{version: binary.BigEndian.Uint16(init[0:2])}
	s := newRefSymmetric(r.version, refPublic(controlPriv))

	var re key32
	copy(re[:], init[5:37])
	s.mixHash(re[:])
	es, err := refDH(controlPriv, re)
	if err != nil {
		return nil, fmt.Errorf("es: %w", err)
	}
	mp, err := s.decryptAndHash(s.mixKey(es), init[37:85])
	if err != nil {
		return nil, fmt.Errorf("machine key: %w", err)
	}
	copy(r.machinePub[:], mp)
	ss, err := refDH(controlPriv, r.machinePub)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	if _, err := s.decryptAndHash(s.mixKey(ss), init[85:101]); err != nil {
		return nil, fmt.Errorf("initiation tag: %w", err)
	}

	eph := refClamp(ephSeed)
	ePub := refPublic(eph)
	r.msg[0] = refMsgResponse
	binary.BigEndian.PutUint16(r.msg[1:3], refRespPayloadLen)
	copy(r.msg[3:35], ePub[:])
	s.mixHash(ePub[:])
	ee, err := refDH(eph, re)
	if err != nil {
		return nil, fmt.Errorf("ee: %w", err)
	}
	s.mixKey(ee)
	se, err := refDH(eph, r.machinePub)
	if err != nil {
		return nil, fmt.Errorf("se: %w", err)
	}
	copy(r.msg[35:51], s.encryptAndHash(s.mixKey(se), nil))
	r.c2s, r.s2c = s.split()
	r.hash = s.h
	return r, nil
}

// refNonce is controlbase's record nonce: four zero bytes, then the counter BIG-endian.
// (Noise's ChaChaPoly puts it little-endian; the two agree on counter 0 only.)
func refNonce(counter uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func refSealRecord(k key32, counter uint64, pt []byte) []byte {
	a, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}
	out := []byte{refMsgRecord, 0, 0}
	binary.BigEndian.PutUint16(out[1:3], uint16(len(pt)+chacha20poly1305.Overhead))
	return a.Seal(out, refNonce(counter), pt, nil)
}

// refSealWrite cuts one write into records the way controlbase's Conn.Write does.
func refSealWrite(k key32, counter *uint64, data []byte) []byte {
	var out []byte
	for len(data) > 0 {
		n := min(len(data), refMaxPlaintext)
		out = append(out, refSealRecord(k, *counter, data[:n])...)
		*counter++
		data = data[n:]
	}
	return out
}

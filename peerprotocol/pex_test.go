// pex_test.go

package peerprotocol

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-i2p-bt/bencode"
	"github.com/go-i2p/go-i2p-bt/metainfo"
	"github.com/go-i2p/i2pkeys"
)

// DebugPrintHex prints the hex representation of data for debugging.
func DebugPrintHex(prefix string, data []byte) {
	if len(data) == 0 {
		log.Printf("%s: [empty data]", prefix)
		return
	}
	log.Printf("%s: len=%d, hex=%s", prefix, len(data), hex.EncodeToString(data))
}

// testPEXHandler handles the extended handshake and i2p_pex messages.
type testPEXHandler struct {
	NoopHandler
	added   []metainfo.Address
	dropped []metainfo.Address
}

func (h *testPEXHandler) OnExtHandShake(pc *PeerConn) error {
	log.Printf("OnExtHandShake called: i2p_pex ID: %d", pc.PEXID)
	return nil
}

func (h *testPEXHandler) OnPayload(pc *PeerConn, extid uint8, payload []byte) error {
	if extid == pc.PEXID && pc.PEXID != 0 {
		um, err := DecodeI2pPexMsg(payload)
		if err != nil {
			return err
		}
		newPeers := parseI2pCompactPeers(um.Added)
		h.added = append(h.added, newPeers...)
		remPeers := parseI2pCompactPeers(um.Dropped)
		h.dropped = append(h.dropped, remPeers...)
	}
	return nil
}

// doTestHandshakeOrdered performs the BT handshake between two peers.
func doTestHandshakeOrdered(pc1, pc2 *PeerConn, t *testing.T) error {
	t.Logf("doTestHandshakeOrdered: start")

	// pc1 -> pc2 handshake
	m1 := HandshakeMsg{ExtensionBits: pc1.ExtBits, PeerID: pc1.ID, InfoHash: pc1.InfoHash}
	buf1 := new(bytes.Buffer)
	buf1.WriteString(ProtocolHeader)
	buf1.Write(m1.ExtensionBits[:])
	buf1.Write(m1.InfoHash[:])
	buf1.Write(m1.PeerID[:])

	var wg sync.WaitGroup
	wg.Add(1)
	var err2 error
	go func() {
		defer wg.Done()
		r2 := make([]byte, 68)
		t.Logf("pc2 reading handshake...")
		if _, err := io.ReadFull(pc2.Conn, r2); err != nil {
			err2 = fmt.Errorf("pc2 read handshake: %v", err)
			return
		}
		if string(r2[:20]) != ProtocolHeader {
			err2 = fmt.Errorf("pc2 invalid protocol header")
			return
		}
		copy(pc2.PeerExtBits[:], r2[20:28])
		copy(pc2.InfoHash[:], r2[28:48])
		copy(pc2.PeerID[:], r2[48:68])
		t.Logf("pc2 read handshake from pc1")
	}()

	t.Logf("pc1 writing handshake (%d bytes)", buf1.Len())
	if _, err := pc1.Conn.Write(buf1.Bytes()); err != nil {
		return fmt.Errorf("pc1 write handshake: %v", err)
	}

	wg.Wait()
	if err2 != nil {
		return err2
	}

	// pc2 -> pc1 handshake
	m2 := HandshakeMsg{ExtensionBits: pc2.ExtBits, PeerID: pc2.ID, InfoHash: pc2.InfoHash}
	buf2 := new(bytes.Buffer)
	buf2.WriteString(ProtocolHeader)
	buf2.Write(m2.ExtensionBits[:])
	buf2.Write(m2.InfoHash[:])
	buf2.Write(m2.PeerID[:])

	wg.Add(1)
	var err1 error
	go func() {
		defer wg.Done()
		r1 := make([]byte, 68)
		t.Logf("pc1 reading handshake from pc2...")
		if _, err := io.ReadFull(pc1.Conn, r1); err != nil {
			err1 = fmt.Errorf("pc1 read handshake: %v", err)
			return
		}
		if string(r1[:20]) != ProtocolHeader {
			err1 = fmt.Errorf("pc1 invalid protocol header")
			return
		}
		copy(pc1.PeerExtBits[:], r1[20:28])
		copy(pc1.InfoHash[:], r1[28:48])
		copy(pc1.PeerID[:], r1[48:68])
		t.Logf("pc1 read handshake from pc2 done")
	}()

	t.Logf("pc2 writing handshake (%d bytes)", buf2.Len())
	if _, err := pc2.Conn.Write(buf2.Bytes()); err != nil {
		return fmt.Errorf("pc2 write handshake: %v", err)
	}
	t.Logf("pc2 wrote handshake")

	wg.Wait()
	if err1 != nil {
		return err1
	}

	return nil
}

// manualEncodeEHMsg encodes the ExtendedHandshakeMsg into a bencoded dictionary using int64 for numeric fields.
func manualEncodeEHMsg(e ExtendedHandshakeMsg) ([]byte, error) {
	m2 := make(map[string]int64, len(e.M))
	for k, v := range e.M {
		m2[k] = int64(v)
	}

	dict := map[string]interface{}{
		"m": m2,
	}
	if e.V != "" {
		dict["v"] = e.V
	}
	if e.Reqq != 0 {
		dict["reqq"] = int64(e.Reqq)
	}
	if e.Port != 0 {
		dict["p"] = int64(e.Port)
	}

	return bencode.EncodeBytes(dict)
}

// doTestExtendedHandshakeOrdered performs an extended handshake between two peers.
func doTestExtendedHandshakeOrdered(pc1, pc2 *PeerConn, e1, e2 ExtendedHandshakeMsg, t *testing.T, pexHandler Handler) error {
	log.Printf("Encoding e1: %+v", e1)
	log.Printf("Encoding e2: %+v", e2)
	log.Printf("e1.M (length=%d): %v", len(e1.M), e1.M)
	log.Printf("e1.V='%s', e1.Reqq=%d, e1.Port=%d", e1.V, e1.Reqq, e1.Port)
	log.Printf("e2.M (length=%d): %v", len(e2.M), e2.M)
	log.Printf("e2.V='%s', e2.Reqq=%d, e2.Port=%d", e2.V, e2.Reqq, e2.Port)

	b1, err := manualEncodeEHMsg(e1)
	if err != nil {
		return fmt.Errorf("encode e1: %v", err)
	}
	DebugPrintHex("Encoded e1", b1)

	b2, err := manualEncodeEHMsg(e2)
	if err != nil {
		return fmt.Errorf("encode e2: %v", err)
	}
	DebugPrintHex("Encoded e2", b2)

	t.Logf("doTestExtendedHandshakeOrdered: e1 len=%d, e2 len=%d", len(b1), len(b2))

	// Verify encoding immediately by decoding
	var testDec1, testDec2 map[string]interface{}
	if err := bencode.DecodeBytes(b1, &testDec1); err != nil {
		log.Printf("Decoding e1 after encoding failed: %v", err)
	} else {
		log.Printf("e1 successfully decoded right after encoding: %+v", testDec1)
	}

	if err := bencode.DecodeBytes(b2, &testDec2); err != nil {
		log.Printf("Decoding e2 after encoding failed: %v", err)
	} else {
		log.Printf("e2 successfully decoded right after encoding: %+v", testDec2)
	}

	msg1 := Message{Type: MTypeExtended, ExtendedID: ExtendedIDHandshake, ExtendedPayload: b1}
	msg2 := Message{Type: MTypeExtended, ExtendedID: ExtendedIDHandshake, ExtendedPayload: b2}

	var wg sync.WaitGroup

	// pc1 -> pc2 extended handshake
	wg.Add(1)
	var err2 error
	go func() {
		defer wg.Done()
		t.Logf("pc2 reading extended handshake...")
		m, err := pc2.ReadMsg()
		if err != nil {
			err2 = fmt.Errorf("pc2 read ext handshake: %v", err)
			return
		}

		DebugPrintHex("pc2 got extended handshake payload", m.ExtendedPayload)

		var tmp map[string]interface{}
		if err := bencode.DecodeBytes(m.ExtendedPayload, &tmp); err != nil {
			err2 = fmt.Errorf("pc2 decode ext handshake: %v", err)
			return
		}
		t.Logf("pc2 got extended handshake from pc1: %+v", tmp)
		pc2.extHandshake = true

		// Handle the message to trigger OnExtHandShake and set PEXID
		if handleErr := pc2.HandleMessage(m, pexHandler); handleErr != nil {
			err2 = fmt.Errorf("pc2 handle extended handshake: %v", handleErr)
			return
		}
	}()

	t.Logf("pc1 writing extended handshake...")
	if err := pc1.WriteMsg(msg1); err != nil {
		return fmt.Errorf("pc1 write ext handshake: %v", err)
	}
	t.Logf("pc1 wrote extended handshake")

	wg.Wait()
	if err2 != nil {
		return err2
	}

	// pc2 -> pc1 extended handshake
	wg.Add(1)
	var err1 error
	go func() {
		defer wg.Done()
		t.Logf("pc1 reading extended handshake...")
		m, err := pc1.ReadMsg()
		if err != nil {
			err1 = fmt.Errorf("pc1 read ext handshake: %v", err)
			return
		}

		DebugPrintHex("pc1 got extended handshake payload", m.ExtendedPayload)

		var tmp map[string]interface{}
		if err := bencode.DecodeBytes(m.ExtendedPayload, &tmp); err != nil {
			err1 = fmt.Errorf("pc1 decode ext handshake: %v", err)
			return
		}
		t.Logf("pc1 got extended handshake from pc2: %+v", tmp)
		pc1.extHandshake = true

		if handleErr := pc1.HandleMessage(m, pexHandler); handleErr != nil {
			err1 = fmt.Errorf("pc1 handle extended handshake: %v", handleErr)
			return
		}
	}()

	t.Logf("pc2 writing extended handshake...")
	if err := pc2.WriteMsg(msg2); err != nil {
		return fmt.Errorf("pc2 write ext handshake: %v", err)
	}
	t.Logf("pc2 wrote extended handshake")

	wg.Wait()
	if err1 != nil {
		return err1
	}

	return nil
}

func TestPEX(t *testing.T) {
	t.Logf("Starting TestPEX")
	serverConn, clientConn := net.Pipe()

	localID := metainfo.NewRandomHash()
	remoteID := metainfo.NewRandomHash()
	infoHash := metainfo.NewRandomHash()

	t.Logf("LocalID=%s RemoteID=%s InfoHash=%s", localID.HexString(), remoteID.HexString(), infoHash.HexString())

	localBits := ExtensionBits{}
	localBits.Set(ExtensionBitExtended)
	remoteBits := ExtensionBits{}
	remoteBits.Set(ExtensionBitExtended)

	localPC := NewPeerConn(serverConn, localID, infoHash)
	localPC.ExtBits = localBits
	localPC.Timeout = 3 * time.Second
	localPC.MaxLength = 256 * 1024
	t.Logf("localPC created")

	remotePC := NewPeerConn(clientConn, remoteID, infoHash)
	remotePC.ExtBits = remoteBits
	remotePC.Timeout = 3 * time.Second
	remotePC.MaxLength = 256 * 1024
	t.Logf("remotePC created")

	pexHandler := &testPEXHandler{}
	t.Logf("testPEXHandler created")

	// Perform handshake
	t.Logf("Performing handshake...")
	if err := doTestHandshakeOrdered(localPC, remotePC, t); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	t.Logf("Handshake done")

	log.Printf("About to encode ExtendedHandshakeMsg with uint8 map values")

	// Extended handshake messages with "i2p_pex"
	localEHMsg := ExtendedHandshakeMsg{
		M: map[string]uint8{
			"ut_metadata": 1,
			"i2p_pex":     2,
			"dummy":       42,
		},
		V:    "nonempty",
		Reqq: 1,
		Port: 6881,
	}
	remoteEHMsg := ExtendedHandshakeMsg{
		M: map[string]uint8{
			"ut_metadata": 1,
			"i2p_pex":     2,
			"dummy":       42,
		},
		V:    "nonempty",
		Reqq: 1,
		Port: 6881,
	}

	t.Logf("Performing extended handshake...")
	if err := doTestExtendedHandshakeOrdered(localPC, remotePC, localEHMsg, remoteEHMsg, t, pexHandler); err != nil {
		t.Fatalf("extended handshake failed: %v", err)
	}
	t.Logf("Extended handshake done")

	// Check that i2p_pex is set now that we've called HandleMessage
	if localPC.PEXID == 0 || remotePC.PEXID == 0 {
		t.Fatalf("i2p_pex not set properly: localPEXID=%d remotePEXID=%d", localPC.PEXID, remotePC.PEXID)
	}
	t.Logf("PEXID local=%d remote=%d", localPC.PEXID, remotePC.PEXID)

	done := make(chan struct{})
	t.Logf("Starting remote read goroutine")
	go func() {
		defer close(done)
		for {
			t.Logf("GOROUTINE: remotePC about to ReadMsg()...")
			msg, err := remotePC.ReadMsg()
			if err != nil {
				t.Logf("GOROUTINE: remotePC.ReadMsg() returned err=%v, exiting goroutine", err)
				return
			}
			t.Logf("GOROUTINE: remotePC.HandleMessage(): msg type=%v", msg.Type)
			if err := remotePC.HandleMessage(msg, pexHandler); err != nil {
				t.Logf("GOROUTINE: remotePC.HandleMessage returned err=%v, exiting goroutine", err)
				return
			}
		}
	}()

	// For i2p_pex, we must provide 32-byte I2P hashes.
	// Here we provide dummy 32-byte data. In real tests, use valid I2P desthashes.
	dummyHash1 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		dummyHash1[i] = 0x01
	}
	i2pAddr1, _ := i2pkeys.DestHashFromBytes(dummyHash1)

	dummyHash2 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		dummyHash2[i] = 0x02
	}
	i2pAddr2, _ := i2pkeys.DestHashFromBytes(dummyHash2)

	addedPeers := []metainfo.Address{
		{IP: i2pAddr1, Port: 6881},
		{IP: i2pAddr2, Port: 6881},
	}

	dummyHashDrop := make([]byte, 32)
	for i := 0; i < 32; i++ {
		dummyHashDrop[i] = 0x03
	}
	i2pAddrDrop, _ := i2pkeys.DestHashFromBytes(dummyHashDrop)

	droppedPeers := []metainfo.Address{
		{IP: i2pAddrDrop, Port: 6881},
	}

	t.Logf("Sending PEX message from local to remote")
	t.Logf("localPC SendPEX...")
	if err := localPC.SendI2PPEX(addedPeers, droppedPeers); err != nil {
		t.Fatalf("SendPEX failed: %v", err)
	}
	t.Logf("PEX message sent. Waiting for remote to process...")

	time.Sleep(300 * time.Millisecond)
	t.Logf("Checking results on remote side")

	// Validate results
	if len(pexHandler.added) != len(addedPeers) {
		t.Fatalf("expected %d added peers, got %d", len(addedPeers), len(pexHandler.added))
	}
	for i, addr := range addedPeers {
		if pexHandler.added[i].String() != addr.String() {
			t.Fatalf("added peer mismatch: got %s, want %s", pexHandler.added[i].String(), addr.String())
		}
	}
	if len(pexHandler.dropped) != len(droppedPeers) {
		t.Fatalf("expected %d dropped peers, got %d", len(droppedPeers), len(pexHandler.dropped))
	}
	for i, addr := range droppedPeers {
		if pexHandler.dropped[i].String() != addr.String() {
			t.Fatalf("dropped peer mismatch: got %s, want %s", pexHandler.dropped[i].String(), addr.String())
		}
	}

	t.Logf("PEX message verification done. Closing connections...")
	serverConn.Close()
	clientConn.Close()
	t.Logf("Connections closed, waiting for goroutine to exit...")

	select {
	case <-done:
		t.Logf("Goroutine exited cleanly")
	case <-time.After(1 * time.Second):
		t.Fatalf("reading goroutine did not exit, still blocked?")
	}
}

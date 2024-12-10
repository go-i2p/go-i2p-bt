package peerprotocol

import (
	"github.com/go-i2p/go-i2p-bt/bencode"
	"github.com/go-i2p/go-i2p-bt/metainfo"
	"github.com/go-i2p/i2pkeys"
)

// I2pPexMsg represents the "i2p_pex" extended message payload.
// Similar to ut_pex but each peer is 32 bytes (no port, just a 32-byte hash).
type I2pPexMsg struct {
	Added    []byte `bencode:"added"`
	AddedF   []byte `bencode:"added.f"`
	Dropped  []byte `bencode:"dropped"`
	DroppedF []byte `bencode:"dropped.f"`
}

// DecodeI2pPexMsg decodes an "i2p_pex" message from bytes.
func DecodeI2pPexMsg(b []byte) (um I2pPexMsg, err error) {
	err = bencode.DecodeBytes(b, &um)
	return
}

// EncodePexMsg encodes a UtPexMsg into bytes.
func EncodeI2pPexMsg(um I2pPexMsg) ([]byte, error) {
	return bencode.EncodeBytes(um)
}

// toI2PCompactPeers converts a list of peers into the i2p_pex compact form.
func toI2PCompactPeers(peers []metainfo.Address) (added []byte, addedf []byte) {
	for _, p := range peers {
		i2p, ok := p.IP.(i2pkeys.I2PAddr)
		if !ok {
			// Not an i2p address, skip
			continue
		}
		dh := i2p.DestHash()
		added = append(added, dh[:]...)
		addedf = append(addedf, 0x00) // flags if needed
	}
	return
}

// parseI2pCompactPeers parses a compact i2p peer list (32 bytes per peer)
func parseI2pCompactPeers(b []byte) []metainfo.Address {
	const peerLen = 32
	var addrs []metainfo.Address
	for i := 0; i+peerLen <= len(b); i += peerLen {
		dh := b[i : i+peerLen]
		i2pAddr, err := i2pkeys.DestHashFromBytes(dh)
		if err != nil {
			continue
		}
		// Use a fixed port or none. Typically port not meaningful for i2p.
		addr := metainfo.Address{IP: i2pAddr, Port: 6881}
		addrs = append(addrs, addr)
	}
	return addrs
}

// SendI2PPEX sends an i2p_pex message to the remote peer.
func (pc *PeerConn) SendI2PPEX(peers []metainfo.Address, dropped []metainfo.Address) error {
	if pc.PEXID == 0 {
		// Peer does not support i2p_pex
		return nil
	}
	um := I2pPexMsg{}
	um.Added, um.AddedF = toI2PCompactPeers(peers)
	um.Dropped, um.DroppedF = toI2PCompactPeers(dropped)
	payload, err := bencode.EncodeBytes(um)
	if err != nil {
		return err
	}
	return pc.SendExtMsg(pc.PEXID, payload)
}

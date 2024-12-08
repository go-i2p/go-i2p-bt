package peerprotocol

import (
	"github.com/go-i2p/go-i2p-bt/bencode"
	"github.com/go-i2p/go-i2p-bt/metainfo"
)

// UtPexMsg represents the "ut_pex" extended message payload (BEP 11).
type UtPexMsg struct {
	Added    []byte `bencode:"added"`
	AddedF   []byte `bencode:"added.f"`
	Dropped  []byte `bencode:"dropped"`
	DroppedF []byte `bencode:"dropped.f"`
}

// DecodePexMsg decodes a "ut_pex" message from bytes.
func DecodePexMsg(b []byte) (um UtPexMsg, err error) {
	err = bencode.DecodeBytes(b, &um)
	return
}

// EncodePexMsg encodes a UtPexMsg into bytes.
func EncodePexMsg(um UtPexMsg) ([]byte, error) {
	return bencode.EncodeBytes(um)
}

// toCompactPeers converts a list of peers (addresses) into the compact form
// required by the ut_pex message. The function returns both the IP/port data
// and the corresponding flags array (added.f/dropped.f). Typically, flags are
// used to indicate if a peer is a seed, but here we just set them to zero.
func toCompactPeers(peers []metainfo.Address) (added []byte, addedf []byte) {
	for _, p := range peers {
		b, err := p.MarshalBinary()
		if err != nil {
			continue
		}
		if len(b) == 6 {
			added = append(added, b...)
			addedf = append(addedf, 0x00) // seed flag or others can be set if needed
		}
	}
	return
}

// parseCompactPeers parses a compact peer list (6 bytes per peer)
// and returns a slice of metainfo.Addresses.
func parseCompactPeers(b []byte) []metainfo.Address {
	var addrs []metainfo.Address
	iplen := 6
	for i := 0; i+iplen <= len(b); i += iplen {
		var addr metainfo.Address
		if err := addr.UnmarshalBinary(b[i : i+iplen]); err == nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// SendPEX sends a ut_pex message to the remote peer, advertising new peers
// (added) and dropped peers (dropped). This method uses the negotiated PEXID
// obtained from the extended handshake (BEP 10 and BEP 11).
// If PEX isn't supported (PEXID=0), it does nothing.
func (pc *PeerConn) SendPEX(peers []metainfo.Address, dropped []metainfo.Address) error {
	if pc.PEXID == 0 {
		// Peer does not support ut_pex
		return nil
	}
	um := UtPexMsg{}
	um.Added, um.AddedF = toCompactPeers(peers)
	um.Dropped, um.DroppedF = toCompactPeers(dropped)
	payload, err := bencode.EncodeBytes(um)
	if err != nil {
		return err
	}
	return pc.SendExtMsg(pc.PEXID, payload)
}

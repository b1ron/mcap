package mcap

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
)

const maxMessageSizeBytes int32 = 48 * 1000 * 1000

// A super simple packet capture...
// sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/go/bin/go to give permission to 'lo' device.
// or run tests as root - sudo /usr/local/go/bin/go.
func Listen(ctx context.Context, key string, port int, out chan bsoncore.Value) error {
	handle, err := pcap.OpenLive("lo", maxMessageSizeBytes, true, pcap.BlockForever)
	if err != nil {
		return err
	}

	filter := "tcp port " + strconv.Itoa(port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return err
	}

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			return err
		}
		if ci.Length == 66 {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			d, err := decode(tcp.Payload)
			if err != nil {
				break
			}

			v, err := d.LookupErr(key)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- v:
			}
		}
	}
	return nil
}

func decode(wm []byte) (bsoncore.Document, error) {
	wmLength := len(wm)
	length, _, _, opcode, wm, ok := wiremessage.ReadHeader(wm)
	if !ok || int(length) > wmLength {
		return nil, errors.New("malformed wire message: insufficient bytes")
	}

	switch opcode {
	case wiremessage.OpMsg:
		_, wm, ok = wiremessage.ReadMsgFlags(wm)
		if !ok {
			return nil, errors.New("malformed wire message: missing OP_MSG flags")
		}

		var res bsoncore.Document
		for len(wm) > 0 {
			var stype wiremessage.SectionType
			stype, wm, ok = wiremessage.ReadMsgSectionType(wm)
			if !ok {
				continue
			}

			switch stype {
			case wiremessage.SingleDocument:
				res, wm, _ = wiremessage.ReadMsgSectionSingleDocument(wm)
			case wiremessage.DocumentSequence:
				_, _, wm, _ = wiremessage.ReadMsgSectionDocumentSequence(wm)
			default:
				continue
			}
		}

		err := res.Validate()
		if err != nil {
			return nil, errors.New("malformed OP_MSG: invalid document")
		}

		return res, err
	default:
		return nil, fmt.Errorf("cannot decode result from %s", opcode)
	}
}

package ingest

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/server/internal/bus"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// JetStreamPublisher zapisuje paczki w strumieniu SIEM_RAW. Nagłówek
// Nats-Msg-Id = batch_id sprawia, że ponowione paczki (np. po zerwanym
// połączeniu) są odrzucane przez JetStream w oknie deduplikacji.
type JetStreamPublisher struct {
	JS jetstream.JetStream
}

func (p *JetStreamPublisher) PublishRaw(ctx context.Context, agentID, batchID string, receivedAt time.Time, gzipBody []byte) (bool, error) {
	msg := &nats.Msg{
		Subject: bus.RawSubject(agentID),
		Data:    gzipBody,
		Header:  nats.Header{},
	}
	msg.Header.Set(bus.HdrAgent, agentID)
	msg.Header.Set(bus.HdrBatch, batchID)
	msg.Header.Set(bus.HdrReceivedAt, receivedAt.Format(time.RFC3339Nano))
	msg.Header.Set(bus.HdrEncoding, "gzip")
	ack, err := p.JS.PublishMsg(ctx, msg, jetstream.WithMsgID(batchID))
	if err != nil {
		return false, err
	}
	return ack.Duplicate, nil
}

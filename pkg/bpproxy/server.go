package bpproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dtn7/dtn7-go/pkg/agent"
	"github.com/dtn7/dtn7-go/pkg/bpv7"
)

type ProxyAgent struct {
	endpoint     bpv7.EndpointID
	receiver     chan agent.Message
	sender       chan agent.Message
	frags        map[string][]bpv7.Bundle
	fragLock     sync.Mutex
	client       *http.Client
	approvedURLs []string
}

func NewProxy(endpoint bpv7.EndpointID, approvedURLs []string) *ProxyAgent {
	p := &ProxyAgent{
		endpoint: endpoint,
		receiver: make(chan agent.Message),
		sender:   make(chan agent.Message),
		frags:    make(map[string][]bpv7.Bundle),
		fragLock: sync.Mutex{},
		client: &http.Client{
			Jar:     nil,
			Timeout: time.Second,
		},
		approvedURLs: approvedURLs,
	}
	go p.handler()
	return p
}

func (p *ProxyAgent) log() *log.Entry {
	return log.WithField("ProxyAgent", p.endpoint)
}

func (p *ProxyAgent) handler() {
	defer close(p.sender)

	for m := range p.receiver {
		switch m := m.(type) {
		case agent.BundleMessage:
			// Skip administrative record bundles.
			if _, err := m.Bundle.AdministrativeRecord(); err == nil {
				continue
			}
			p.handleBundle(m.Bundle)
		case agent.ShutdownMessage:
			return

		default:
			p.log().WithField("message", m).Info("Received unsupported Message")
		}
	}
}

func (p *ProxyAgent) handleBundle(bundle bpv7.Bundle) {
	if !bundle.ID().IsFragment {
		go func() {
			if err := p.ProxyBundle(bundle); err != nil {
				p.log().WithField("error", err).Info("Failed to proxy bundle")
			}
		}()
		return
	}

	p.handleFragment(bundle)
}

func (p *ProxyAgent) handleFragment(bundle bpv7.Bundle) {
	if !bundle.ID().IsFragment {
		return
	}

	p.fragLock.Lock()
	defer p.fragLock.Unlock()

	id := bundle.PrimaryBlock.ReportTo.String()
	frags, ok := p.frags[id]
	if !ok {
		p.frags[id] = []bpv7.Bundle{bundle}
		return
	}

	p.frags[id] = append(frags, bundle)
	if !bpv7.IsBundleReassemblable(p.frags[id]) {
		return
	}

	reassembled, err := bpv7.ReassembleFragments(p.frags[id])
	if err != nil {
		p.log().WithField("error", err).Info("Failed to reassemble bundles")
		return
	}

	var wg sync.WaitGroup
	for _, f := range append(p.frags[id], reassembled) {
		wg.Add(1)
		go func() {
			if err := p.ProxyBundle(f); err != nil {
				p.log().WithField("error", err).Info("Failed to proxy bundle")
			}
			wg.Done()
		}()
	}

	wg.Wait()
	delete(p.frags, id)
}

func (p *ProxyAgent) ProxyBundle(bundle bpv7.Bundle) error {
	var req HTTPMessage
	if err := ExtractHTTPMessage(&bundle, &req); err != nil {
		return err
	}

	if !slices.ContainsFunc(p.approvedURLs, func(s string) bool {
		return strings.HasPrefix(req.URL, s)
	}) {
		return errors.New("received proxy bundle to unapproved URL")
	}

	r, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer(req.Body))
	if err != nil {
		return err
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}
	r.Header.Set("Cookie", fmt.Sprintf("session=%s", req.Session))

	resp, err := p.client.Do(r)
	if err != nil {
		return err
	}
	payload, err := buildResponsePayload(resp)
	if err != nil {
		return err
	}
	resp.Body.Close()

	hopCount := 4
	if hc, err := bundle.ExtensionBlock(bpv7.ExtBlockTypeHopCountBlock); err == nil {
		hopCount = int(hc.Value.(*bpv7.HopCountBlock).Limit)
	}

	bndl, err := bpv7.Builder().
		CRC(bpv7.CRC32).
		Source(p.endpoint).
		Destination(bundle.PrimaryBlock.ReportTo).
		CreationTimestampNow().
		Lifetime(bundle.PrimaryBlock.Lifetime).
		HopCountBlock(hopCount).
		PayloadBlock(payload).
		Build()
	if err != nil {
		return err
	}

	p.log().WithField("bundle", bndl).Info("Sending Response Bundle")
	p.sender <- agent.BundleMessage{
		Bundle: bndl,
	}
	return nil
}

func (p *ProxyAgent) Endpoints() []bpv7.EndpointID {
	return []bpv7.EndpointID{p.endpoint}
}

func (p *ProxyAgent) MessageReceiver() chan agent.Message {
	return p.receiver
}

func (p *ProxyAgent) MessageSender() chan agent.Message {
	return p.sender
}

func buildResponsePayload(r *http.Response) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = v[0]
	}

	resp := HTTPMessage{
		Status:  r.StatusCode,
		Headers: headers,
		Body:    body,
	}

	return json.Marshal(resp)
}

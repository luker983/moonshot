package bpproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dtn7/dtn7-go/pkg/agent"
	"github.com/dtn7/dtn7-go/pkg/bpv7"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
)

const (
	timeout       = 5 * time.Second
	rps           = 10
	max_body_size = 16384
)

type HTTPMessage struct {
	Method  string
	Status  int
	URL     string
	Headers map[string]string
	Body    []byte
	Session string
}

func Start(nodeEndpoint, peerEndpoint, wsAddr string) {

	mux := http.NewServeMux()
	mux.Handle("/", httprate.LimitByIP(rps, time.Second)(ProxyRequest(wsAddr, nodeEndpoint, peerEndpoint)))
	httpServer := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       timeout,
		ReadHeaderTimeout: timeout,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Println("proxy err: %w", err)
		}
	}()
}

func ProxyRequest(wsAddr, nodeEndpoint, peerEndpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		payload, err := buildRequestPayload(r, http.MaxBytesReader(w, r.Body, max_body_size))
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadRequest)
			return
		}

		clientEndpoint := nodeEndpoint + uuid.NewString()
		b, err := bpv7.Builder().
			CRC(bpv7.CRC32).
			Source(clientEndpoint).
			Destination(peerEndpoint).
			CreationTimestampNow().
			Lifetime("10s").
			HopCountBlock(4).
			PayloadBlock(payload).
			Build()
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadRequest)
			return
		}

		conn, err := agent.NewWebSocketAgentConnector(fmt.Sprintf("ws://%s/ws", wsAddr), clientEndpoint)
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadRequest)
			return
		}
		defer conn.Close()

		if err := conn.WriteBundle(b); err != nil {
			http.Error(w, "proxy error", http.StatusBadRequest)
			return
		}

		go func() {
			<-time.After(timeout)
			conn.Close()
		}()

		for {
			b, err := conn.ReadBundle()
			if err != nil {
				http.Error(w, "proxy error", http.StatusBadRequest)
				return
			}
			// Skip administrative record bundles.
			if _, err := b.AdministrativeRecord(); err == nil {
				continue
			}

			var resp HTTPMessage
			if err := ExtractHTTPMessage(&b, &resp); err != nil {
				http.Error(w, "proxy error", http.StatusBadRequest)
				return
			}
			for k, v := range resp.Headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(resp.Status)
			w.Write(resp.Body)
			return
		}
	}
}

func buildRequestPayload(r *http.Request, b io.ReadCloser) ([]byte, error) {
	body, err := io.ReadAll(b)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = v[0]
	}

	var session string
	if s, _ := r.Cookie("session"); s != nil {
		session = s.Value
	}

	req := HTTPMessage{
		Method:  r.Method,
		Headers: headers,
		URL:     fmt.Sprintf("http://%s%s?%s", r.Host, r.URL.Path, r.URL.RawQuery),
		Body:    body,
		Session: session,
	}

	return json.Marshal(req)
}

func ExtractHTTPMessage(bundle *bpv7.Bundle, msg *HTTPMessage) error {
	payloadBlock, err := bundle.PayloadBlock()
	if err != nil {
		return err
	}

	block, ok := payloadBlock.Value.(*bpv7.PayloadBlock)
	if !ok {
		return errors.New("couldn't parse payload block")
	}

	if err := json.Unmarshal(block.Data(), msg); err != nil {
		return err
	}

	return nil
}

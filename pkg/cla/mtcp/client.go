// https://github.com/dtn7/dtn7-go/blob/v0.9.1/pkg/cla/mtcp/client.go
//
// Increases TCP dial timeout and sets MTU to allow for earth<->moon latency.
package mtcp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dtn7/cboring"

	"github.com/dtn7/dtn7-go/pkg/bpv7"
	"github.com/dtn7/dtn7-go/pkg/cla"
)

// MTCPClient is an implementation of a Minimal TCP Convergence-Layer client
// which connects to a MTCP server to send bundles. This struct implements
// a ConvergenceSender.
type MTCPClient struct {
	conn       net.Conn
	peer       bpv7.EndpointID
	mutex      sync.Mutex
	reportChan chan cla.ConvergenceStatus

	permanent bool
	address   string

	stopSyn chan struct{}
	stopAck chan struct{}

	mtu int
}

// NewMTCPClient creates a new MTCPClient, connected to the given address for
// the registered endpoint ID. The permanent flag indicates if this MTCPClient
// should never be removed from the core.
func NewMTCPClient(address string, peer bpv7.EndpointID, permanent bool, mtu int) *MTCPClient {
	return &MTCPClient{
		peer:      peer,
		permanent: permanent,
		address:   address,
		mtu:       mtu,
	}
}

// NewAnonymousMTCPClient creates a new MTCPClient, connected to the given address.
// The permanent flag indicates if this MTCPClient should never be removed from
// the core.
func NewAnonymousMTCPClient(address string, permanent bool) *MTCPClient {
	return NewMTCPClient(address, bpv7.DtnNone(), permanent, 4096)
}

func (client *MTCPClient) Start() (err error, retry bool) {
	retry = true

	conn, connErr := dial(client.address)
	if connErr != nil {
		err = connErr
		return
	}

	client.reportChan = make(chan cla.ConvergenceStatus)
	client.stopSyn = make(chan struct{})
	client.stopAck = make(chan struct{})

	client.conn = conn

	go client.handler()
	return
}

func (client *MTCPClient) handler() {
	var ticker = time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Introduce ourselves once
	client.reportChan <- cla.NewConvergencePeerAppeared(client, client.GetPeerEndpointID())

	for {
		select {
		case <-client.stopSyn:
			_ = client.conn.Close()

			close(client.reportChan)
			close(client.stopAck)

			return

		case <-ticker.C:
			client.mutex.Lock()
			err := cboring.WriteByteStringLen(0, client.conn)
			client.mutex.Unlock()

			if err != nil {
				log.WithFields(log.Fields{
					"client": client.String(),
					"error":  err,
				}).Error("MTCPClient: Keepalive erred")

				client.reportChan <- cla.NewConvergencePeerDisappeared(client, client.GetPeerEndpointID())
			}
		}
	}
}

func (client *MTCPClient) Send(bndl bpv7.Bundle) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("MTCPClient.Send: %v", r)
		}
	}()

	defer func() {
		if err != nil {
			client.reportChan <- cla.NewConvergencePeerDisappeared(client, client.GetPeerEndpointID())
		}
	}()

	client.mutex.Lock()
	defer client.mutex.Unlock()

	frags, fragErr := bndl.Fragment(client.mtu)
	if fragErr != nil {
		err = fragErr
		return
	}

	for _, f := range frags {
		connWriter := bufio.NewWriter(client.conn)

		buff := new(bytes.Buffer)
		if cborErr := cboring.Marshal(&f, buff); cborErr != nil {
			err = cborErr
			return
		}

		if bsErr := cboring.WriteByteStringLen(uint64(buff.Len()), connWriter); bsErr != nil {
			err = bsErr
			return
		}

		if _, plErr := buff.WriteTo(connWriter); plErr != nil {
			err = plErr
			return
		}

		if flushErr := connWriter.Flush(); flushErr != nil {
			err = flushErr
			return
		}

		// Check if the connection is still alive with an empty, unbuffered packet
		if probeErr := cboring.WriteByteStringLen(0, client.conn); probeErr != nil {
			err = probeErr
			return
		}
	}

	return
}

func (client *MTCPClient) Channel() chan cla.ConvergenceStatus {
	return client.reportChan
}

func (client *MTCPClient) Close() error {
	close(client.stopSyn)
	<-client.stopAck

	return nil
}

func (client *MTCPClient) GetPeerEndpointID() bpv7.EndpointID {
	return client.peer
}

func (client *MTCPClient) Address() string {
	return client.address
}

func (client *MTCPClient) IsPermanent() bool {
	return client.permanent
}

func (client *MTCPClient) String() string {
	if client.conn != nil {
		return fmt.Sprintf("mtcp://%v", client.conn.RemoteAddr())
	} else {
		return fmt.Sprintf("mtcp://%s", client.address)
	}
}

func dial(address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second, // Increased from 1 to 5 seconds.
		KeepAlive: 5 * time.Second,
	}
	return dialer.Dial("tcp", address)
}

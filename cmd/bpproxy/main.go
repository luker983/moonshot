// bpproxy proxies HTTP traffic through a delay/disruption tolerant network.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/dtn7/dtn7-go/pkg/agent"
	"github.com/dtn7/dtn7-go/pkg/bpv7"
	"github.com/dtn7/dtn7-go/pkg/cla"
	"github.com/dtn7/dtn7-go/pkg/cla/mtcp"
	"github.com/dtn7/dtn7-go/pkg/routing"
	"github.com/gorilla/mux"

	"lunalink/pkg/bpproxy"
	mymtcp "lunalink/pkg/cla/mtcp"
)

type config struct {
	nodeURI          string
	peerURI          string
	peerAddr         string
	storePath        string
	approvedURLs     []string
	routingConf      routing.RoutingConf
	cronCheckBundles time.Duration
	cronCleanStore   time.Duration
	cronCleanID      time.Duration
	claPort          int
	wsAddr           string
	proxyAddr        string
}

var defaultConfig = config{
	nodeURI:   "dtn://earth-1/",
	peerURI:   "dtn://moon-1/",
	peerAddr:  "lunalink",
	storePath: "./earth.store",
	approvedURLs: []string{
		"http://lander:8080",
	},
	routingConf: routing.RoutingConf{
		Algorithm: "epidemic",
	},
	cronCheckBundles: time.Second * 10,
	cronCleanStore:   time.Minute * 1,
	cronCleanID:      time.Minute * 1,
	claPort:          1337,
	wsAddr:           "0.0.0.0:8081",
	proxyAddr:        "0.0.0.0:8080",
}

func init() {
	flag.StringVar(&defaultConfig.nodeURI, "node", defaultConfig.nodeURI, "dtn uri of this node")
	flag.StringVar(&defaultConfig.peerURI, "peer", defaultConfig.peerURI, "dtn uri of peer node")
	flag.StringVar(&defaultConfig.peerAddr, "peername", defaultConfig.peerAddr, "hostname or ip address of peer")
	flag.StringVar(&defaultConfig.storePath, "store", defaultConfig.storePath, "bundle store directory")
}

func main() {
	flag.Parse()
	c := defaultConfig

	c.startDTN()
	bpproxy.Start(c.nodeURI, c.peerURI+"bpproxy", c.wsAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

// startDTN configures convergence layers and endpoint names for transporting bundles
// between nodes.
//
// Simplified version of https://github.com/dtn7/dtn7-go/tree/master/cmd/dtnd
func (c *config) startDTN() {
	nodeID, err := bpv7.NewEndpointID(c.nodeURI)
	if err != nil {
		log.Fatal(err)
	}
	peerID, err := bpv7.NewEndpointID(c.peerURI)
	if err != nil {
		log.Fatal(err)
	}

	core, err := routing.NewCore(c.storePath, nodeID, true, c.routingConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	cron := routing.NewCron()
	if err := cron.Register("pending_bundles", core.CheckPendingBundles, c.cronCheckBundles); err != nil {
		log.Fatal(err)
	}
	if err := cron.Register("clean_store", core.Store.DeleteExpired, c.cronCleanStore); err != nil {
		log.Fatal(err)
	}
	if err := cron.Register("clean_ids", core.IdKeeper.Clean, c.cronCleanID); err != nil {
		log.Fatal(err)
	}
	core.Cron = cron

	bpproxyID, err := bpv7.NewEndpointID(c.nodeURI + "bpproxy")
	if err != nil {
		log.Fatal(err)
	}
	core.RegisterApplicationAgent(bpproxy.NewProxy(bpproxyID, c.approvedURLs))

	r := mux.NewRouter()
	ws := agent.NewWebSocketAgent()
	r.HandleFunc("/ws", ws.ServeHTTP)
	httpServer := &http.Server{
		Addr:              c.wsAddr,
		Handler:           r,
		ReadHeaderTimeout: 60 * time.Second,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Println("ws err: %w", err)
		}
	}()
	core.RegisterApplicationAgent(ws)

	listener := mtcp.NewMTCPServer(fmt.Sprintf(":%d", c.claPort), nodeID, true)
	core.RegisterCLA(listener, cla.MTCP, nodeID)

	peer := mymtcp.NewMTCPClient(net.JoinHostPort(c.peerAddr, fmt.Sprint(c.claPort)), peerID, true, 4096)
	core.RegisterConvergable(peer)
}

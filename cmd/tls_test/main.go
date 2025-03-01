package main

import (
	"sync"

	"github.com/kiwiz/popgun"
	"github.com/kiwiz/popgun/backends"
)

func main() {
	cfg := popgun.Config{
		ListenInterface: "localhost:1443"}
	auth := backends.DummyAuthorizator{}
	be := backends.DummyBackend{}
	server := popgun.NewServer(cfg, auth, be)
	server.StartTLS("../../cert/cert.pem", "../../cert/key.pem")
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

package main

import (
	"net/http"

	"github.com/google/gopacket"
)

type Server struct {
	PacketSource *gopacket.PacketSource
	MsgData []string
}

func main() {
	e := EthernetHelper{}
	e.SetName("lo")
	handle, err := e.openStream()
	if err != nil {
		panic(err)
	}

	e.Handle = handle

	s := Server{}
	s.PacketSource = e.AcquirePacketChannel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.IndexRoot)

	http.ListenAndServe(":8080", mux)
}
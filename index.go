package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/google/gopacket/layers"
)

func (s *Server) IndexRoot(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("./views/index.html")
	if err != nil {
		panic(err)
	}

	go func()  {
		for packet := range s.PacketSource.Packets() {
			if len(packet.TransportLayer().LayerPayload()) == 0 {
				continue
			}

			if ethlayer := packet.Layer(layers.LayerTypeEthernet); ethlayer != nil {
				eth, _ := ethlayer.(*layers.Ethernet)
				if eth.SrcMAC.String() != (CP_SRC_MAC.String()) {
					continue
				}
			}
			s.MsgData = append(s.MsgData, fmt.Sprintf("%x", (packet.TransportLayer().LayerPayload())))
		}
	}()

	t.Execute(w, s.MsgData)
}
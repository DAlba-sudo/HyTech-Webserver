package main

import (
	"encoding/binary"
)

type CanPack struct {
	Time uint64
	MsgId uint8
	MsgLen uint8
	Data uint64
}

func (cp *CanPack) ToByte() ([]byte) {
	var buf []byte
	buf = binary.LittleEndian.AppendUint64(buf, cp.Time)
	buf = binary.LittleEndian.AppendUint16(buf, (uint16(cp.MsgId) << 8) | uint16(cp.MsgLen))
	buf = binary.LittleEndian.AppendUint64(buf, cp.Data)

	return buf
}

func (cp *CanPack) Decode(buf *[]byte) {
	
}
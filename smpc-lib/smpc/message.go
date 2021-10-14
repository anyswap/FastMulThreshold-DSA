package smpc

import (
)

type Message interface {
	GetFromID() string // x,fi(x) ---> id,skui
	GetFromIndex() int
	GetToID() []string
	IsBroadcast() bool
	OutMap() map[string]string
}

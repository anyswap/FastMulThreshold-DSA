package smpc

type Round interface {
	Start() error
	CanAccept(msg Message) bool
	Update() (bool, error)
	NextRound() Round
	RoundNumber() int
	CanProceed() bool
	GetIds() (SortableIDSSlice, error)
	GetDNodeIDIndex(id string) (int, error)
}

package metrics

import (
	"encoding/json"
	"io"
	"time"
)

// MarshalJSON returns a byte slice containing a JSON representation of all
// the metrics in the Registry.
func (r *StandardRegistry) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.GetAll())
}

// WriteJSON writes metrics from the given registry  periodically to the
// specified io.Writer as JSON.
func WriteJSON(r Registry, d time.Duration, w io.Writer) error {
	for range time.Tick(d) {
	    err := WriteJSONOnce(r, w)
	    if err != nil {
		return err 
	    }
	}

	return nil
}

// WriteJSONOnce writes metrics from the given registry to the specified
// io.Writer as JSON.
func WriteJSONOnce(r Registry, w io.Writer) error {
    err := json.NewEncoder(w).Encode(r)
    if err != nil {
	return err
    }

    return nil
}

func (p *PrefixedRegistry) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.GetAll())
}

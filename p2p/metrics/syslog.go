// +build !windows

package metrics

import (
	"fmt"
	"log/syslog"
	"time"
)

// Output each metric in the given registry to syslog periodically using
// the given syslogger.
func Syslog(r Registry, d time.Duration, w *syslog.Writer) {
	for range time.Tick(d) {
		r.Each(func(name string, i interface{}) {
			switch metric := i.(type) {
			case Counter:
			    	s := fmt.Sprintf("counter %s: count: %d", name, metric.Count())
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case Gauge:
			    	s := fmt.Sprintf("gauge %s: value: %d", name, metric.Value())
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case GaugeFloat64:
			    	s := fmt.Sprintf("gauge %s: value: %f", name, metric.Value())
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case Healthcheck:
				metric.Check()
				s := fmt.Sprintf("healthcheck %s: error: %v", name, metric.Error())
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case Histogram:
				h := metric.Snapshot()
				ps := h.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
				s := fmt.Sprintf(
					"histogram %s: count: %d min: %d max: %d mean: %.2f stddev: %.2f median: %.2f 75%%: %.2f 95%%: %.2f 99%%: %.2f 99.9%%: %.2f",
					name,
					h.Count(),
					h.Min(),
					h.Max(),
					h.Mean(),
					h.StdDev(),
					ps[0],
					ps[1],
					ps[2],
					ps[3],
					ps[4],
				)
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case Meter:
				m := metric.Snapshot()
				s := fmt.Sprintf(
					"meter %s: count: %d 1-min: %.2f 5-min: %.2f 15-min: %.2f mean: %.2f",
					name,
					m.Count(),
					m.Rate1(),
					m.Rate5(),
					m.Rate15(),
					m.RateMean(),
				)
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			case Timer:
				t := metric.Snapshot()
				ps := t.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
				s := fmt.Sprintf(
					"timer %s: count: %d min: %d max: %d mean: %.2f stddev: %.2f median: %.2f 75%%: %.2f 95%%: %.2f 99%%: %.2f 99.9%%: %.2f 1-min: %.2f 5-min: %.2f 15-min: %.2f mean-rate: %.2f",
					name,
					t.Count(),
					t.Min(),
					t.Max(),
					t.Mean(),
					t.StdDev(),
					ps[0],
					ps[1],
					ps[2],
					ps[3],
					ps[4],
					t.Rate1(),
					t.Rate5(),
					t.Rate15(),
					t.RateMean(),
				)
				err := w.Info(s)
				if err != nil {
				    fmt.Println(s)
				}
			}
		})
	}
}

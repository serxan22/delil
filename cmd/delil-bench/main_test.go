package main

import (
	"context"
	"testing"
	"time"
)

func TestEngineDetectsTampering(t *testing.T) {
	res, err := runEngine(context.Background(), options{events: 200})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TamperDetected || res.TamperSequence != 101 || res.TamperReason != "payload_hash_mismatch" {
		t.Fatalf("unexpected tamper result: %+v", res)
	}
}

func TestPercentile(t *testing.T) {
	var d []time.Duration
	for i := 1; i <= 100; i++ {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	for p, want := range map[int]float64{50: 50, 95: 95, 99: 99, 100: 100} {
		if got := pct(d, p); got != want {
			t.Errorf("p%d = %v, want %v", p, got, want)
		}
	}
	if pct(nil, 50) != 0 {
		t.Error("empty input")
	}
}

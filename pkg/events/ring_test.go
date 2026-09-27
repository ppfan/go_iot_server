package events

import (
	"fmt"
	"testing"
)

func TestRingNewestFirstAndBounded(t *testing.T) {
	r := NewRing(3)
	if len(r.List()) != 0 {
		t.Fatal("new ring not empty")
	}
	for i := 1; i <= 5; i++ {
		r.Add("n1", []byte(fmt.Sprint(i)))
	}
	got := r.List()
	if len(got) != 3 || got[0].Body != "5" || got[2].Body != "3" {
		t.Fatalf("List() = %+v", got)
	}
}

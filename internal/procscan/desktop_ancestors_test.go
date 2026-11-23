package procscan

import "testing"

func TestDesktopAncestorsRequireCompleteChain(t *testing.T) {
	complete := map[int]int{301: 100, 100: 4}
	ancestors, known := desktopAncestors(complete, 301)
	if !known || !ancestors[301] || !ancestors[100] {
		t.Fatalf("expected both ancestors: %v, complete %v", ancestors, known)
	}
	for _, parents := range []map[int]int{
		{301: 100},
		{301: 100, 100: 301},
	} {
		if _, known := desktopAncestors(parents, 301); known {
			t.Fatalf("accepted an incomplete or cyclic ancestry: %v", parents)
		}
	}
}

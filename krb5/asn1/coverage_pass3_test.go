package asn1

import "testing"

func TestASN1ContextTagBoundaries(t *testing.T) {
	for _, tag := range []int{0, 1, 30} {
		encoded, err := WrapContext(tag, []byte{0x02, 0x01, 0x01})
		if err != nil {
			t.Fatalf("tag %d: %v", tag, err)
		}
		if _, err := UnwrapContext(encoded, tag); err != nil {
			t.Fatalf("unwrap tag %d: %v", tag, err)
		}
	}
	for _, tag := range []int{-1, 31, 1 << 20} {
		if _, err := WrapContext(tag, nil); err == nil {
			t.Fatalf("invalid tag %d accepted", tag)
		}
	}
	if _, err := UnwrapContext([]byte{0x80}, 0); err == nil {
		t.Fatal("truncated context accepted")
	}
}

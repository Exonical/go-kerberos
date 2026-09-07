package kdb

import (
	"bytes"
	"testing"
)

func TestMasterKeyTLDataCodecs(t *testing.T) {
	if got, err := EncodeMKVNO(0x1234); err != nil || !bytes.Equal(got, []byte{0x34, 0x12}) {
		t.Fatalf("MKVNO encoding: %x %v", got, err)
	}
	act := []ActKVNO{{KVNO: 2, ActTime: 0x01020304}, {KVNO: 1, ActTime: -1}}
	encoded, err := EncodeACTKVNO(act)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 0, 2, 0, 4, 3, 2, 1, 1, 0, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("ACTKVNO encoding: got %x want %x", encoded, want)
	}
	decoded, err := DecodeACTKVNO(want)
	if err != nil || len(decoded) != len(act) || decoded[0] != act[0] || decoded[1] != act[1] {
		t.Fatalf("ACTKVNO decoding: %#v %v", decoded, err)
	}
	aux := []MKeyAuxEntry{{MKeyKVNO: 1, LatestKeyKVNO: 2,
		LatestKeyEnctype: 18, LatestKeyData: []byte{2, 0, 1, 2}}}
	auxBytes, err := EncodeMKEYAux(aux)
	if err != nil {
		t.Fatal(err)
	}
	auxWant := []byte{1, 0, 1, 0, 2, 0, 18, 0, 4, 0, 2, 0, 1, 2}
	if !bytes.Equal(auxBytes, auxWant) {
		t.Fatalf("MKEY_AUX encoding: got %x want %x", auxBytes, auxWant)
	}
	auxDecoded, err := DecodeMKEYAux(auxWant)
	if err != nil || len(auxDecoded) != 1 || !bytes.Equal(auxDecoded[0].LatestKeyData, aux[0].LatestKeyData) {
		t.Fatalf("MKEY_AUX decoding: %#v %v", auxDecoded, err)
	}
}

func TestMasterKeyTLDataRejectsMalformedValues(t *testing.T) {
	if _, err := DecodeMKVNO([]byte{1}); err == nil {
		t.Fatal("short MKVNO accepted")
	}
	if _, err := DecodeACTKVNO([]byte{1, 0}); err == nil {
		t.Fatal("short ACTKVNO accepted")
	}
	if _, err := DecodeACTKVNO([]byte{2, 0, 1, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("unsupported ACTKVNO version accepted")
	}
	if _, err := DecodeMKEYAux([]byte{1, 0, 1, 0, 2, 0, 18, 0, 4, 0, 1}); err == nil {
		t.Fatal("truncated MKEY_AUX accepted")
	}
}

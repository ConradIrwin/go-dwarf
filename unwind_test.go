package dwarf

import (
	"debug/macho"
	"testing"
)

func TestUnwindBasics(t *testing.T) {
	f, err := macho.Open("testdata/x")

	if err != nil {
		t.Fatal(err)
	}

	d, err := LoadFromMachO(f)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[uintptr]uintptr{
		0x2000: 0x10008,
		0x2005: 0x10008,
		0x2022: 0x10008,
		0x2023: 0x10010,
		0x2030: 0x10008,
		0x2049: 0x10008,
		0x204a: 0x10008,
		0x2069: 0x10010,
		0x206a: 0x10010,
	}

	for pc, result := range tests {
		cfa, err := d.CanonicalFrameAddress(pc, 0x10000)
		if err != nil {
			t.Fatal(err)
		}

		if cfa != result {
			t.Errorf("CFA @ %x = %x (not %x)", pc, cfa, result)
		}

	}

}

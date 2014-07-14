package dwarf

import (
	"github.com/mitchellh/osext"
	"debug/macho"
)

func LoadForSelf() (*Data, error) {

	path, err := osext.Executable()

	if err != nil {
		return nil, err
	}

	file, err := macho.Open(path)

	if err != nil {
		return nil, err
	}

	return LoadFromMachO(file)
}

func LoadFromMachO(f *macho.File) (*Data, error) {
	var names = [...]string{"abbrev", "info", "str", "frame"}
    var dat [len(names)][]byte
    for i, name := range names {
        name = "__debug_" + name
        s := f.Section(name)
        if s == nil {
            dat[i] = []byte{}
            continue
        }
        b, err := s.Data()
        if err != nil && uint64(len(b)) < s.Size {
            return nil, err
        }
        dat[i] = b
    }

    abbrev, info, str, frame := dat[0], dat[1], dat[2], dat[3]

    return New(abbrev, nil, frame, info, nil, nil, nil, str)
}

package dwarf

import (
	"fmt"
)

// Get an attribute from the dwarf entry by type.
func (entry *Entry) Attribute(attr Attr) interface{} {
	for _, f := range(entry.Field) {
        if (f.Attr == attr) {
            return f.Val
        }
    }
    return nil

}

// Calculate the location of this entry relative to the
// canonical frame address.
func (entry *Entry) Location(cfa uintptr) (uintptr, error) {

	loclist, ok := entry.Attribute(AttrLocation).([]byte)

	if !ok {
		return 0, fmt.Errorf("No AttrLocation in Entry")
	}

	return parseLocList(loclist, locInfo{CanonicalFrameAddress: cfa})
}

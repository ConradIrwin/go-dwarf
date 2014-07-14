package dwarf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	dw_CFA_nop                = 0x00
	dw_CFA_set_loc            = 0x01 // address
	dw_CFA_advance_loc1       = 0x02 // 1-byte delta
	dw_CFA_advance_loc2       = 0x03 // 2-byte delta
	dw_CFA_advance_loc4       = 0x04 // 4-byte delta
	dw_CFA_offset_extended    = 0x05 // ULEB128 register, ULEB128 offset
	dw_CFA_restore_extended   = 0x06 // ULEB128 register
	dw_CFA_undefined          = 0x07 // ULEB128 register
	dw_CFA_same_value         = 0x08 // ULEB128 register
	dw_CFA_register           = 0x09 // ULEB128 register, ULEB128 register
	dw_CFA_remember_state     = 0x0a
	dw_CFA_restore_state      = 0x0b
	dw_CFA_def_cfa            = 0x0c // ULEB128 register, ULEB128 offset
	dw_CFA_def_cfa_register   = 0x0d // ULEB128 register
	dw_CFA_def_cfa_offset     = 0x0e // ULEB128 offset
	dw_CFA_def_cfa_expression = 0x0f // BLOCK
	dw_CFA_expression         = 0x10 // ULEB128 register, BLOCK
	dw_CFA_offset_extended_sf = 0x11 // ULEB128 register, SLEB128 offset
	dw_CFA_def_cfa_sf         = 0x12 // ULEB128 register, SLEB128 offset
	dw_CFA_def_cfa_offset_sf  = 0x13 // SLEB128 offset
	dw_CFA_val_offset         = 0x14 // ULEB128, ULEB128
	dw_CFA_val_offset_sf      = 0x15 // ULEB128, SLEB128
	dw_CFA_val_expression     = 0x16 // ULEB128, BLOCK

	dw_CFA_lo_user = 0x1c
	dw_CFA_hi_user = 0x3f

	// Opcodes that take an addend operand.
	dw_CFA_advance_loc = 0x1 << 6 // +delta
	dw_CFA_offset      = 0x2 << 6 // +register (ULEB128 offset)
	dw_CFA_restore     = 0x3 << 6 // +register
)

type CommonInformationEntry struct {
	CodeAlignmentFactor uintptr
	DataAlignmentFactor int64
	ReturnColumn        byte

	InitialLocation uintptr
	AddressRange    uintptr
	Instructions    []byte

	StackRegister uint64

	StackOffset int64
	ColumnValue int64
	order    binary.ByteOrder
}

func (d *Data) CanonicalFrameAddress(pc uintptr, sp uintptr) (uintptr, error) {

	stream := bytes.NewReader(d.frame)

	for {
		var length, id uint32
		var pcstart, pccount uint64

		err := binary.Read(stream, d.order, &length)
		if err != nil {
			return 0, err
		}

		if length < 4 {
			return 0, fmt.Errorf("dwarf/unwind: entry too short")
		}

		err = binary.Read(stream, d.order, &id)
		if err != nil {
			return 0, err
		}

		if id == 0xFFFFFFFF {
			stream.Seek(int64(length) - 4, 1)
			continue
		}

		if length < 20 {
			return 0, fmt.Errorf("dwarf/unwind: frame description entry too short")
		}

		err = binary.Read(stream, d.order, &pcstart)
		if err != nil {
			return 0, err
		}
		err = binary.Read(stream, d.order, &pccount)
		if err != nil {
			return 0, err
		}

		if uintptr(pcstart) <= pc && pc < uintptr(pcstart+pccount) {
			cie, err := d.parseCommonInformationEntry(id)
			if err != nil {
				return 0, err
			}
			cie.InitialLocation = uintptr(pcstart)
			cie.AddressRange = uintptr(pccount)
			cie.Instructions = make([]byte, length-20)
			cie.order = d.order
			_, err = stream.Read(cie.Instructions)
			if err != nil {
				return 0, err
			}
			return cie.CanonicalFrameAddress(pc, sp)
		} else {
			stream.Seek(int64(length) - 20, 1)
		}
	}

	return 0, fmt.Errorf("dwarf/unwind: frame data didn't include pc")
}

func (d *Data) parseCommonInformationEntry(id uint32) (*CommonInformationEntry, error) {

	stream := bytes.NewReader(d.frame)
	stream.Seek(int64(id), 0)

	var length, mark uint32

	err := binary.Read(stream, d.order, &length)
	if err != nil {
		return nil, err
	}

	entry := make([]byte, length)
	_, err = stream.Read(entry)
	if err != nil {
		return nil, err
	}
	stream = bytes.NewReader(entry)

	err = binary.Read(stream, d.order, &mark)
	if err != nil {
		return nil, err
	}

	if length < 4 || mark != 0xFFFFFFFF {
		return nil, fmt.Errorf("dwarf/unwind: No CommonInformationEntry found at d.frames:%x", id)
	}

	version, err := stream.ReadByte()
	if err != nil {
		return nil, err
	}

	if version != 3 {
		return nil, fmt.Errorf("dwarf/unwind: unsupported dwarf version: %x", version)
	}

	augmentation, err := stream.ReadByte()
	if err != nil {
		return nil, err
	}

	if augmentation != 0 {
		return nil, fmt.Errorf("dwarf/unwind: unhandled dwarf augmentation")
	}

	codeAlignment, err := parseUnsignedLEB128(stream)
	if err != nil {
		return nil, err
	}
	dataAlignment, err := parseSignedLEB128(stream)
	if err != nil {
		return nil, err
	}

	returnColumn, err := stream.ReadByte()
	if err != nil {
		return nil, err
	}

	cie := &CommonInformationEntry{}
	cie.CodeAlignmentFactor = uintptr(codeAlignment)
	cie.DataAlignmentFactor = dataAlignment
	cie.ReturnColumn = returnColumn

	err = cie.Update(stream)
	if err == io.EOF {
		return cie, nil
	}
	return nil, err
}

func (cie *CommonInformationEntry) Update(stream *bytes.Reader) error {

	for {
		instruction, err := stream.ReadByte()
		if err != nil {
			return err
		}

		switch instruction {
		case dw_CFA_def_cfa:
			reg, err := parseUnsignedLEB128(stream)
			if err != nil {
				return err
			}
			val, err := parseUnsignedLEB128(stream)
			if err != nil {
				return err
			}
			cie.StackRegister = reg
			cie.StackOffset = int64(val)

		case dw_CFA_nop:
			// No-op

		case dw_CFA_offset + cie.ReturnColumn:

			raw, err := parseSignedLEB128(stream)
			if err != nil {
				return err
			}
			cie.ColumnValue = raw * cie.DataAlignmentFactor

		default:

			return fmt.Errorf("Unsuported CFA op: %x", instruction)
		}
	}

	return nil
}

func (cie *CommonInformationEntry) CanonicalFrameAddress(pc uintptr, sp uintptr) (uintptr, error) {
	loc := cie.InitialLocation
	fmt.Println("loc :", loc, loc + cie.AddressRange, cie.Instructions)
	offset := cie.StackOffset

	stream := bytes.NewReader(cie.Instructions)

	for {
		instruction, err := stream.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		if instruction == dw_CFA_def_cfa_offset_sf {
			delta, err := parseSignedLEB128(stream)
			if err != nil {
				return 0, err
			}
			offset = delta * cie.DataAlignmentFactor
			fmt.Println("offset: ", delta * cie.DataAlignmentFactor)

		} else {
			// This is a change-of-address command
			if loc > pc {
				break
			}
			if instruction == dw_CFA_advance_loc1 {
				var delta int8
				err := binary.Read(stream, cie.order, &delta)
				if err != nil {
					return 0, err
				}
				loc += uintptr(delta) * cie.CodeAlignmentFactor
				fmt.Println("loc :", loc)

			} else if instruction == dw_CFA_advance_loc2 {
				var delta int16
				err := binary.Read(stream, cie.order, &delta)
				if err != nil {
					return 0, err
				}
				loc += uintptr(delta) * cie.CodeAlignmentFactor
				fmt.Println("loc :", loc)

			} else if instruction >= dw_CFA_advance_loc && instruction <= 0x80 {
				loc += uintptr(instruction - 0x40) * cie.CodeAlignmentFactor
				fmt.Println("loc :", loc)
			} else {
				return 0, fmt.Errorf("dwarf/unwind: unknown op-code: %x", instruction)
			}
		}
	}

	return uintptr(int64(sp) + offset), nil
}

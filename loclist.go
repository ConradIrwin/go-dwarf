package dwarf

import (
	"bytes"
	"errors"
	"io"
	"log"
)

type locInfo struct {
	CanonicalFrameAddress uintptr
}

const (
	dw_OP_addr                = 0x03 /* Constant address.  */
	dw_OP_deref               = 0x06
	dw_OP_const1u             = 0x08 /* Unsigned 1-byte constant.  */
	dw_OP_const1s             = 0x09 /* Signed 1-byte constant.  */
	dw_OP_const2u             = 0x0a /* Unsigned 2-byte constant.  */
	dw_OP_const2s             = 0x0b /* Signed 2-byte constant.  */
	dw_OP_const4u             = 0x0c /* Unsigned 4-byte constant.  */
	dw_OP_const4s             = 0x0d /* Signed 4-byte constant.  */
	dw_OP_const8u             = 0x0e /* Unsigned 8-byte constant.  */
	dw_OP_const8s             = 0x0f /* Signed 8-byte constant.  */
	dw_OP_constu              = 0x10 /* Unsigned LEB128 constant.  */
	dw_OP_consts              = 0x11 /* Signed LEB128 constant.  */
	dw_OP_dup                 = 0x12
	dw_OP_drop                = 0x13
	dw_OP_over                = 0x14
	dw_OP_pick                = 0x15 /* 1-byte stack index.  */
	dw_OP_swap                = 0x16
	dw_OP_rot                 = 0x17
	dw_OP_xderef              = 0x18
	dw_OP_abs                 = 0x19
	dw_OP_and                 = 0x1a
	dw_OP_div                 = 0x1b
	dw_OP_minus               = 0x1c
	dw_OP_mod                 = 0x1d
	dw_OP_mul                 = 0x1e
	dw_OP_neg                 = 0x1f
	dw_OP_not                 = 0x20
	dw_OP_or                  = 0x21
	dw_OP_plus                = 0x22
	dw_OP_plus_uconst         = 0x23 /* Unsigned LEB128 addend.  */
	dw_OP_shl                 = 0x24
	dw_OP_shr                 = 0x25
	dw_OP_shra                = 0x26
	dw_OP_xor                 = 0x27
	dw_OP_bra                 = 0x28 /* Signed 2-byte constant.  */
	dw_OP_eq                  = 0x29
	dw_OP_ge                  = 0x2a
	dw_OP_gt                  = 0x2b
	dw_OP_le                  = 0x2c
	dw_OP_lt                  = 0x2d
	dw_OP_ne                  = 0x2e
	dw_OP_skip                = 0x2f /* Signed 2-byte constant.  */
	dw_OP_lit0                = 0x30 /* Literal 0.  */
	dw_OP_lit1                = 0x31 /* Literal 1.  */
	dw_OP_lit2                = 0x32 /* Literal 2.  */
	dw_OP_lit3                = 0x33 /* Literal 3.  */
	dw_OP_lit4                = 0x34 /* Literal 4.  */
	dw_OP_lit5                = 0x35 /* Literal 5.  */
	dw_OP_lit6                = 0x36 /* Literal 6.  */
	dw_OP_lit7                = 0x37 /* Literal 7.  */
	dw_OP_lit8                = 0x38 /* Literal 8.  */
	dw_OP_lit9                = 0x39 /* Literal 9.  */
	dw_OP_lit10               = 0x3a /* Literal 10.  */
	dw_OP_lit11               = 0x3b /* Literal 11.  */
	dw_OP_lit12               = 0x3c /* Literal 12.  */
	dw_OP_lit13               = 0x3d /* Literal 13.  */
	dw_OP_lit14               = 0x3e /* Literal 14.  */
	dw_OP_lit15               = 0x3f /* Literal 15.  */
	dw_OP_lit16               = 0x40 /* Literal 16.  */
	dw_OP_lit17               = 0x41 /* Literal 17.  */
	dw_OP_lit18               = 0x42 /* Literal 18.  */
	dw_OP_lit19               = 0x43 /* Literal 19.  */
	dw_OP_lit20               = 0x44 /* Literal 20.  */
	dw_OP_lit21               = 0x45 /* Literal 21.  */
	dw_OP_lit22               = 0x46 /* Literal 22.  */
	dw_OP_lit23               = 0x47 /* Literal 23.  */
	dw_OP_lit24               = 0x48 /* Literal 24.  */
	dw_OP_lit25               = 0x49 /* Literal 25.  */
	dw_OP_lit26               = 0x4a /* Literal 26.  */
	dw_OP_lit27               = 0x4b /* Literal 27.  */
	dw_OP_lit28               = 0x4c /* Literal 28.  */
	dw_OP_lit29               = 0x4d /* Literal 29.  */
	dw_OP_lit30               = 0x4e /* Literal 30.  */
	dw_OP_lit31               = 0x4f /* Literal 31.  */
	dw_OP_reg0                = 0x50 /* Register 0.  */
	dw_OP_reg1                = 0x51 /* Register 1.  */
	dw_OP_reg2                = 0x52 /* Register 2.  */
	dw_OP_reg3                = 0x53 /* Register 3.  */
	dw_OP_reg4                = 0x54 /* Register 4.  */
	dw_OP_reg5                = 0x55 /* Register 5.  */
	dw_OP_reg6                = 0x56 /* Register 6.  */
	dw_OP_reg7                = 0x57 /* Register 7.  */
	dw_OP_reg8                = 0x58 /* Register 8.  */
	dw_OP_reg9                = 0x59 /* Register 9.  */
	dw_OP_reg10               = 0x5a /* Register 10.  */
	dw_OP_reg11               = 0x5b /* Register 11.  */
	dw_OP_reg12               = 0x5c /* Register 12.  */
	dw_OP_reg13               = 0x5d /* Register 13.  */
	dw_OP_reg14               = 0x5e /* Register 14.  */
	dw_OP_reg15               = 0x5f /* Register 15.  */
	dw_OP_reg16               = 0x60 /* Register 16.  */
	dw_OP_reg17               = 0x61 /* Register 17.  */
	dw_OP_reg18               = 0x62 /* Register 18.  */
	dw_OP_reg19               = 0x63 /* Register 19.  */
	dw_OP_reg20               = 0x64 /* Register 20.  */
	dw_OP_reg21               = 0x65 /* Register 21.  */
	dw_OP_reg22               = 0x66 /* Register 22.  */
	dw_OP_reg23               = 0x67 /* Register 24.  */
	dw_OP_reg24               = 0x68 /* Register 24.  */
	dw_OP_reg25               = 0x69 /* Register 25.  */
	dw_OP_reg26               = 0x6a /* Register 26.  */
	dw_OP_reg27               = 0x6b /* Register 27.  */
	dw_OP_reg28               = 0x6c /* Register 28.  */
	dw_OP_reg29               = 0x6d /* Register 29.  */
	dw_OP_reg30               = 0x6e /* Register 30.  */
	dw_OP_reg31               = 0x6f /* Register 31.  */
	dw_OP_breg0               = 0x70 /* Base register 0.  */
	dw_OP_breg1               = 0x71 /* Base register 1.  */
	dw_OP_breg2               = 0x72 /* Base register 2.  */
	dw_OP_breg3               = 0x73 /* Base register 3.  */
	dw_OP_breg4               = 0x74 /* Base register 4.  */
	dw_OP_breg5               = 0x75 /* Base register 5.  */
	dw_OP_breg6               = 0x76 /* Base register 6.  */
	dw_OP_breg7               = 0x77 /* Base register 7.  */
	dw_OP_breg8               = 0x78 /* Base register 8.  */
	dw_OP_breg9               = 0x79 /* Base register 9.  */
	dw_OP_breg10              = 0x7a /* Base register 10.  */
	dw_OP_breg11              = 0x7b /* Base register 11.  */
	dw_OP_breg12              = 0x7c /* Base register 12.  */
	dw_OP_breg13              = 0x7d /* Base register 13.  */
	dw_OP_breg14              = 0x7e /* Base register 14.  */
	dw_OP_breg15              = 0x7f /* Base register 15.  */
	dw_OP_breg16              = 0x80 /* Base register 16.  */
	dw_OP_breg17              = 0x81 /* Base register 17.  */
	dw_OP_breg18              = 0x82 /* Base register 18.  */
	dw_OP_breg19              = 0x83 /* Base register 19.  */
	dw_OP_breg20              = 0x84 /* Base register 20.  */
	dw_OP_breg21              = 0x85 /* Base register 21.  */
	dw_OP_breg22              = 0x86 /* Base register 22.  */
	dw_OP_breg23              = 0x87 /* Base register 23.  */
	dw_OP_breg24              = 0x88 /* Base register 24.  */
	dw_OP_breg25              = 0x89 /* Base register 25.  */
	dw_OP_breg26              = 0x8a /* Base register 26.  */
	dw_OP_breg27              = 0x8b /* Base register 27.  */
	dw_OP_breg28              = 0x8c /* Base register 28.  */
	dw_OP_breg29              = 0x8d /* Base register 29.  */
	dw_OP_breg30              = 0x8e /* Base register 30.  */
	dw_OP_breg31              = 0x8f /* Base register 31.  */
	dw_OP_regx                = 0x90 /* Unsigned LEB128 register.  */
	dw_OP_fbreg               = 0x91 /* Signed LEB128 offset.  */
	dw_OP_bregx               = 0x92 /* ULEB128 register followed by SLEB128 off. */
	dw_OP_piece               = 0x93 /* ULEB128 size of piece addressed. */
	dw_OP_deref_size          = 0x94 /* 1-byte size of data retrieved.  */
	dw_OP_xderef_size         = 0x95 /* 1-byte size of data retrieved.  */
	dw_OP_nop                 = 0x96
	dw_OP_push_object_address = 0x97
	dw_OP_call2               = 0x98
	dw_OP_call4               = 0x99
	dw_OP_call_ref            = 0x9a
	dw_OP_form_tls_address    = 0x9b /* TLS offset to address in current thread */
	dw_OP_call_frame_cfa      = 0x9c /* CFA as determined by CFI.  */
	dw_OP_bit_piece           = 0x9d /* ULEB128 size and ULEB128 offset in bits.  */
	dw_OP_implicit_value      = 0x9e /* dw_FORM_block follows opcode.  */
	dw_OP_stack_value         = 0x9f /* No operands, special like dw_OP_piece.  */

	/* GNU extensions.  */
	dw_OP_GNU_push_tls_address = 0xe0
	dw_OP_GNU_uninit           = 0xf0
	dw_OP_GNU_encoded_addr     = 0xf1
	dw_OP_GNU_implicit_pointer = 0xf2
	dw_OP_GNU_entry_value      = 0xf3
	dw_OP_GNU_const_type       = 0xf4
	dw_OP_GNU_regval_type      = 0xf5
	dw_OP_GNU_deref_type       = 0xf6
	dw_OP_GNU_convert          = 0xf7
	dw_OP_GNU_reinterpret      = 0xf9

	dw_OP_lo_user = 0xe0 /* Implementation-defined range start.  */
	dw_OP_hi_user = 0xff /* Implementation-defined range end.  */
)

const (
	dw_LEB_EXTENSION = 0x80
	dw_LEB_BITS      = 0xff ^ dw_LEB_EXTENSION
)

func parseLocList(locList []byte, info locInfo) (addr uintptr, err error) {

	var stack []int64

	stream := bytes.NewReader(locList)

	for {
		log.Println("Stack: %%", stack)
		instruction, err := stream.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		switch instruction {
		case dw_OP_consts:

			n, err := parseSignedLEB128(stream)
			if err != nil {
				return 0, err
			}

			stack = append(stack, n)

		case dw_OP_plus:

			if len(stack) < 2 {
				return 0, errors.New("Invalid location list")
			}

			a := stack[len(stack)-1]
			b := stack[len(stack)-2]

			stack = append(stack[:len(stack)-2], a+b)

		case dw_OP_call_frame_cfa:
			stack = append(stack, int64(info.CanonicalFrameAddress))

		default:
			return 0, errors.New("Unsupported location OP")
		}

	}

	if len(stack) == 1 {
		return uintptr(stack[0]), nil
	} else {
		return 0, errors.New("Invalid location list")
	}
}

// TODO: big.Int? check for overflow!
func parseSignedLEB128(stream *bytes.Reader) (int64, error) {

	n := uint64(0)
	shift := uint(0)

	for {
		b, err := stream.ReadByte()
		if err != nil {
			return 0, err
		}

		n = uint64(b&dw_LEB_BITS)<<shift | n
		shift += 7

		if b&dw_LEB_EXTENSION == 0 {
			break
		}
	}

	m := int64(n)

	if n&(1<<(shift-1)) != 0 {
		m = int64(n) - int64(1<<shift)
	}

	return m, nil
}

func parseUnsignedLEB128(stream *bytes.Reader) (uint64, error) {
	n := uint64(0)
	shift := uint(0)

	for {
		b, err := stream.ReadByte()
		if err != nil {
			return 0, err
		}

		n = uint64(b&dw_LEB_BITS)<<shift | n
		shift += 7

		if b&dw_LEB_EXTENSION == 0 {
			break
		}
	}

	return n, nil
}

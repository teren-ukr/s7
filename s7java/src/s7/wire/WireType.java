// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.wire;

/** The wire types of S7_Network_Wire_Protocol_v1.md section 8. */
public enum WireType {
    I8(0x0001, Kind.INT, 8, false), U8(0x0002, Kind.UINT, 8, false),
    I12(0x0003, Kind.INT, 12, false), U12(0x0004, Kind.UINT, 12, false),
    I16(0x0005, Kind.INT, 16, false), U16(0x0006, Kind.UINT, 16, false),
    I32(0x0007, Kind.INT, 32, false), U32(0x0008, Kind.UINT, 32, false),
    I64(0x0009, Kind.INT, 64, false), U64(0x000A, Kind.UINT, 64, false),
    I128(0x000B, Kind.INT, 128, false), U128(0x000C, Kind.UINT, 128, false),
    F16(0x000D, Kind.FLOAT, 16, false), F32(0x000E, Kind.FLOAT, 32, false),
    F64(0x000F, Kind.FLOAT, 64, false), F128(0x0010, Kind.FLOAT, 128, false),
    C16(0x0101, Kind.FLOAT, 16, true), C32(0x0102, Kind.FLOAT, 32, true),
    C64(0x0103, Kind.FLOAT, 64, true), C128(0x0104, Kind.FLOAT, 128, true),
    CI8(0x0201, Kind.INT, 8, true), CU8(0x0202, Kind.UINT, 8, true),
    CI16(0x0203, Kind.INT, 16, true), CI32(0x0204, Kind.INT, 32, true),
    CI64(0x0205, Kind.INT, 64, true), CI128(0x0206, Kind.INT, 128, true);

    /** Of each component. */
    public enum Kind { INT, UINT, FLOAT }

    public final int id;
    public final Kind kind;
    public final int bits; // per component
    public final boolean complex;

    WireType(int id, Kind kind, int bits, boolean complex) {
        this.id = id;
        this.kind = kind;
        this.bits = bits;
        this.complex = complex;
    }

    public int components() {
        return complex ? 2 : 1;
    }

    public static WireType byId(int id) {
        for (WireType t : values()) {
            if (t.id == id) {
                return t;
            }
        }
        return null;
    }

    public static WireType parse(String name) {
        try {
            return valueOf(name);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("unknown signal type '" + name + "'");
        }
    }
}

import random
import struct


def r(rs, rt, rd, sa, fn):
    return ((rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | fn) & 0xffffffff


def i(op, rs, rt, imm):
    return ((op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)) & 0xffffffff


def lw(rt, off, rs): return i(0x23, rs, rt, off)
def lh(rt, off, rs): return i(0x21, rs, rt, off)
def lhu(rt, off, rs): return i(0x25, rs, rt, off)
def sw(rt, off, rs): return i(0x2b, rs, rt, off)
def sb(rt, off, rs): return i(0x28, rs, rt, off)
def sh(rt, off, rs): return i(0x29, rs, rt, off)
def andi(rt, rs, imm): return i(0x0c, rs, rt, imm)
def xor(rd, rs, rt): return r(rs, rt, rd, 0, 0x26)
def addu(rd, rs, rt): return r(rs, rt, rd, 0, 0x21)
def or_(rd, rs, rt): return r(rs, rt, rd, 0, 0x25)
def sll(rd, rt, sa): return r(0, rt, rd, sa, 0x00)
def srl(rd, rt, sa): return r(0, rt, rd, sa, 0x02)
def sra(rd, rt, sa): return r(0, rt, rd, sa, 0x03)
def rotr(rd, rt, sa): return r(1, rt, rd, sa, 0x02)
def jr(rs): return r(rs, 0, 0, 0, 0x08)
def beq(rs, rt, imm): return i(0x04, rs, rt, imm)
def addiu(rt, rs, imm): return i(0x09, rs, rt, imm)
def xori(rt, rs, imm): return i(0x0e, rs, rt, imm)


def load_u32(register, value):
    """Materialize a 32-bit value without requiring LUI support."""
    return (
        addiu(register, 0, (value >> 16) & 0xffff),
        sll(register, register, 16),
        xori(register, register, value & 0xffff),
    )


def emit_route(term0, term1, rotation0, rotation1, variant=0):
    """Update the hidden two-word route receipt with polymorphic registers."""
    rng = random.Random((variant ^ 0x524F555445) & ((1 << 64) - 1))
    pool = [2, 3, *range(5, 16), *range(17, 26)]
    first, second, constant, auxiliary, shifted = rng.sample(pool, 5)
    out = [lw(first, 0x24, 16), lw(second, 0x28, 16)]
    out.extend(load_u32(constant, term0))
    out.append(xor(first, first, constant))
    if variant & 1:
        out.extend((srl(auxiliary, first, rotation0), sll(shifted, first, 32 - rotation0),
                    or_(first, auxiliary, shifted)))
    else:
        out.append(rotr(first, first, rotation0))
    out.append(addu(first, first, second))
    out.extend(load_u32(constant, term1))
    out.append(xor(second, second, constant))
    if variant & 2:
        out.extend((srl(auxiliary, second, rotation1), sll(shifted, second, 32 - rotation1),
                    or_(second, auxiliary, shifted)))
    else:
        out.append(rotr(second, second, rotation1))
    out.extend((addu(second, second, first), sw(first, 0x24, 16), sw(second, 0x28, 16)))
    return out


def emit_op(
    kind,
    d,
    s,
    rot,
    arg_index,
    byte_index=0,
    delay_trap=False,
    variant=0,
):
    """Emit one semantic operation through a per-function polymorphic template."""
    rng = random.Random(variant & ((1 << 64) - 1))
    pool = [2, 3, *range(5, 16), *range(17, 26)]
    (
        destination,
        source,
        work,
        constant,
        state_base,
        arg_base,
        auxiliary,
        shift_left,
        dead,
        store_base,
    ) = rng.sample(pool, 10)
    state_bias = rng.choice((-0x54, -0x20, 0x18, 0x3c, 0x70))
    arg_bias = rng.choice((-0x34, -0x10, 0x14, 0x48))
    store_bias = rng.choice((-0x68, -0x24, 0x2c, 0x64))
    out = [
        addiu(state_base, 16, state_bias),
        addiu(arg_base, 4, arg_bias),
        # The delay instruction executes, while the plausible destination
        # store immediately after it is dead code.
        beq(0, 0, 2),
        xor(dead, dead, dead),
        sw(dead, d * 4 - state_bias, state_base),
    ]

    destination_load = [lw(destination, d * 4 - state_bias, state_base)]
    if kind == "zext16" and rng.randrange(2):
        source_load = [lhu(source, s * 4 - state_bias, state_base)]
    elif kind == "sext16" and rng.randrange(2):
        source_load = [lh(source, s * 4 - state_bias, state_base)]
    else:
        source_load = [lw(source, s * 4 - state_bias, state_base)]
        if kind == "zext16":
            source_load.append(andi(source, source, 0xffff))
        elif kind == "sext16":
            source_load.extend((sll(source, source, 16), sra(source, source, 16)))
    out.extend(source_load + destination_load if rng.randrange(2) else destination_load + source_load)

    if delay_trap:
        out.extend((beq(0, 0, 1), xor(work, destination, source), 0))
    elif variant % 3 == 0:
        out.append(xor(work, destination, source))
    elif variant % 3 == 1:
        out.extend((addu(work, destination, 0), xor(work, work, source)))
    else:
        mask = (variant ^ 0xA5C3) & 0xffff
        out.extend(
            (
                xori(auxiliary, source, mask),
                xori(auxiliary, auxiliary, mask),
                xor(work, destination, auxiliary),
            )
        )

    out.append(lw(constant, arg_index * 4 - arg_bias, arg_base))
    if variant & 4:
        out.extend((addu(auxiliary, work, 0), addu(work, auxiliary, constant)))
    else:
        out.append(addu(work, work, constant))

    if variant & 8:
        out.extend((srl(auxiliary, work, rot), sll(shift_left, work, 32 - rot), or_(work, auxiliary, shift_left)))
    else:
        out.append(rotr(work, work, rot))

    # A real but irrelevant write creates additional state-relative stores.
    out.extend((xor(dead, dead, dead), sw(dead, 0x2c + (variant % 5) * 4, 16)))
    out.append(addiu(store_base, 16, store_bias))
    destination_offset = d * 4 - store_bias
    if kind == "byte":
        out.append(sb(work, destination_offset + byte_index, store_base))
    elif kind == "half":
        out.append(sh(work, destination_offset, store_base))
    else:
        out.append(sw(work, destination_offset, store_base))
    return out


def emit_gadget(desc, trap=False):
    words = emit_op(*desc[0], delay_trap=trap)
    words += emit_op(*desc[1])
    words += [jr(31), 0]
    return b"".join(struct.pack("<I", w) for w in words)

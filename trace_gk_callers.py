#!/usr/bin/env python3

import bisect
import re
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from revprogress import Progress


PATH = "/mnt/ios/Payload/OurNotes/Frameworks/bangdreamournotes.dylib"

# ------------------------------------------------------------
# 已確認的 classes
# ------------------------------------------------------------

GK_CLASS = 0xCED6C0
LH_CLASS = 0xCEE1B0


# ------------------------------------------------------------
# 我們目前最在意的 selectors
# ------------------------------------------------------------

INTERESTING_SELECTORS = {
    # LHxbz builder family
    "BwBYYWSRHrFwKalynUkKrDGP",
    "bJyyvPEHsYhWvmkKUoVwUiTAFRoBbQhXYnspWQiWZPUWWME",
    "FkpuboJwwUOjlJsoeWtdYcmPtZnQIeGxfuGgQAWUGXqaBpwOXiAGOHaXKYeWCUT",
    "TtuIgrYTXvVhPbySMrcklGPBoAhVsHZGDfEShogNPUXPgLqLLUwenuwTILmNokGEPnrxVSzH",

    # Gk factories
    "jDejqlMWWHKMOLFJqGfsOcVeIFnNlwHMugYlgpVCFgjB",
    "HcfYIpPuQoREagyRCTuGsDMumAoZFfUEZajcGMWXOd",

    # Gk initialization / validation
    "pzwSlKYUoLJfDNwWsMSEZiYCQprygLHRPzviNFzuuYtSGYqeUTCkiWZorrSIVFNcg",
    "VXMbO",
    "hwgizNbPooZ",
    "YVYhfTBBIqJRBDGpiLIEacJXEJlrg",

    # Gk fields
    "type",
    "setType:",
    "active",
    "setActive:",
    "offset",
    "setOffset:",
    "signature",
    "setSignature:",
    "range",
    "setRange:",
    "searchDirection",
    "setSearchDirection:",
    "identifier",
    "setIdentifier:",
    "architecture",

    # Collection / object-building operations we've already seen
    "addObject:",
    "mutableCopy",
    "integerValue",

    # LH storage accessors
    "eobUBoT",
    "mZhQGvYuHAr",
    "JgvsdWlEbCqSUnH",
    "tqjvFEMLMVUDxOxJpCx",
}


# ------------------------------------------------------------
# Scoring
# ------------------------------------------------------------

WEIGHTS = {
    "CLASS:GkOEznX": 15,
    "CLASS:LHxbzDSewNaAjVygv": 14,

    "SEL:FkpuboJwwUOjlJsoeWtdYcmPtZnQIeGxfuGgQAWUGXqaBpwOXiAGOHaXKYeWCUT": 14,
    "SEL:bJyyvPEHsYhWvmkKUoVwUiTAFRoBbQhXYnspWQiWZPUWWME": 10,
    "SEL:TtuIgrYTXvVhPbySMrcklGPBoAhVsHZGDfEShogNPUXPgLqLLUwenuwTILmNokGEPnrxVSzH": 10,

    "SEL:jDejqlMWWHKMOLFJqGfsOcVeIFnNlwHMugYlgpVCFgjB": 12,
    "SEL:HcfYIpPuQoREagyRCTuGsDMumAoZFfUEZajcGMWXOd": 10,

    "SEL:setOffset:": 8,
    "SEL:setSignature:": 8,
    "SEL:setRange:": 6,
    "SEL:setSearchDirection:": 6,
    "SEL:setType:": 6,
    "SEL:setActive:": 5,
    "SEL:setIdentifier:": 4,

    "SEL:addObject:": 3,
    "SEL:mutableCopy": 2,
    "SEL:integerValue": 2,

    "SEL:JgvsdWlEbCqSUnH": 3,
    "SEL:tqjvFEMLMVUDxOxJpCx": 3,
}


# ------------------------------------------------------------
# Load file
# ------------------------------------------------------------

try:
    with open(PATH, "rb") as f:
        data = f.read()
except Exception as e:
    print(f"ERROR opening target: {e}", file=sys.stderr)
    raise


def u32(off):
    return struct.unpack_from("<I", data, off)[0]


def u64(off):
    return struct.unpack_from("<Q", data, off)[0]


def sign_extend(v, bits):
    sign = 1 << (bits - 1)
    return (v ^ sign) - sign


def raw_cstr(off):
    if off is None:
        return None

    if off < 0 or off >= len(data):
        return None

    end = data.find(b"\0", off)

    if end < 0:
        return None

    try:
        return data[off:end].decode("utf-8", "replace")
    except Exception:
        return None


# ------------------------------------------------------------
# Mach-O parse
# ------------------------------------------------------------

if len(data) < 32:
    raise SystemExit("ERROR: file too small")

magic = u32(0)

if magic != 0xFEEDFACF:
    raise SystemExit(
        f"ERROR: unexpected Mach-O magic 0x{magic:08x}"
    )

ncmds = u32(16)

segments = []
sections = {}

function_starts_info = None

off = 32

for _ in range(ncmds):
    if off + 8 > len(data):
        break

    cmd = u32(off)
    cmdsize = u32(off + 4)

    if cmdsize < 8:
        break

    # LC_SEGMENT_64
    if cmd == 0x19:

        segname = (
            data[off + 8:off + 24]
            .split(b"\0")[0]
            .decode("ascii", "replace")
        )

        vmaddr = u64(off + 24)
        vmsize = u64(off + 32)

        fileoff = u64(off + 40)
        filesize = u64(off + 48)

        nsects = u32(off + 64)

        segments.append({
            "name": segname,
            "vmaddr": vmaddr,
            "vmsize": vmsize,
            "fileoff": fileoff,
            "filesize": filesize,
        })

        sec_off = off + 72

        for i in range(nsects):

            s = sec_off + i * 80

            if s + 80 > len(data):
                break

            sectname = (
                data[s:s + 16]
                .split(b"\0")[0]
                .decode("ascii", "replace")
            )

            secseg = (
                data[s + 16:s + 32]
                .split(b"\0")[0]
                .decode("ascii", "replace")
            )

            addr = u64(s + 32)
            size = u64(s + 40)
            file_offset = u32(s + 48)

            sections[(secseg, sectname)] = {
                "addr": addr,
                "size": size,
                "offset": file_offset,
            }

    # LC_FUNCTION_STARTS
    elif cmd == 0x26:

        function_starts_info = (
            u32(off + 8),
            u32(off + 12),
        )

    off += cmdsize


def vm_to_off(vm):

    for seg in segments:

        start = seg["vmaddr"]
        end = start + seg["filesize"]

        if start <= vm < end:
            return seg["fileoff"] + (vm - start)

    return None


def vm_cstr(vm):

    o = vm_to_off(vm)

    if o is None:
        return None

    return raw_cstr(o)


text_sec = sections.get(("__TEXT", "__text"))

if not text_sec:
    raise SystemExit("ERROR: cannot find __TEXT,__text")


TEXT_ADDR = text_sec["addr"]
TEXT_SIZE = text_sec["size"]
TEXT_OFF = text_sec["offset"]

text_bytes = data[
    TEXT_OFF:
    TEXT_OFF + TEXT_SIZE
]


print("=== TARGET ===")
print(f"file       = {PATH}")
print(
    f"__text     = "
    f"0x{TEXT_ADDR:x} .. "
    f"0x{TEXT_ADDR + TEXT_SIZE:x}"
)
print(f"size       = {TEXT_SIZE:,} bytes")
print(f"Gk class_t = 0x{GK_CLASS:x}")
print(f"LH class_t = 0x{LH_CLASS:x}")
print()


# ------------------------------------------------------------
# Objective-C class/method metadata
# ------------------------------------------------------------

class_names = {}

# imp -> ["-[Class selector]", "+[Class selector]"]
method_names = defaultdict(list)


def parse_class(class_vm, prefix="-"):

    class_off = vm_to_off(class_vm)

    if class_off is None:
        return None

    if class_off + 40 > len(data):
        return None

    bits = u64(class_off + 32)

    # ObjC class_data_bits_t low flag bits
    ro_vm = bits & ~0x7

    ro_off = vm_to_off(ro_vm)

    if ro_off is None:
        return None

    if ro_off + 40 > len(data):
        return None

    name_vm = u64(ro_off + 24)
    methods_vm = u64(ro_off + 32)

    class_name = vm_cstr(name_vm)

    if not class_name:
        return None

    class_names[class_vm] = class_name

    method_off = vm_to_off(methods_vm)

    if method_off is None:
        return class_name

    if method_off + 8 > len(data):
        return class_name

    entsize_flags = u32(method_off)
    count = u32(method_off + 4)

    entsize = entsize_flags & 0xFFFF

    # This dylib's ordinary ObjC method lists are 24-byte absolute entries.
    if entsize < 24 or entsize > 64:
        return class_name

    for i in range(count):

        e = method_off + 8 + i * entsize

        if e + 24 > len(data):
            break

        name_ptr = u64(e)
        type_ptr = u64(e + 8)
        imp = u64(e + 16)

        selector = vm_cstr(name_ptr)

        if not selector:
            continue

        method_names[imp].append(
            f"{prefix}[{class_name} {selector}]"
        )

    return class_name


classlist_sections = [
    sec
    for (segname, sectname), sec in sections.items()
    if sectname == "__objc_classlist"
]

for sec in classlist_sections:

    count = sec["size"] // 8

    for i in range(count):

        p = sec["offset"] + i * 8

        if p + 8 > len(data):
            break

        cls = u64(p)

        if not cls:
            continue

        parse_class(cls, "-")

        cls_off = vm_to_off(cls)

        if cls_off is None:
            continue

        if cls_off + 8 > len(data):
            continue

        meta = u64(cls_off)

        if meta:
            parse_class(meta, "+")


# ------------------------------------------------------------
# Selector refs
# ------------------------------------------------------------

selector_slots = defaultdict(list)

selref_sections = [
    sec
    for (segname, sectname), sec in sections.items()
    if sectname == "__objc_selrefs"
]

for sec in selref_sections:

    count = sec["size"] // 8

    for i in range(count):

        slot_vm = sec["addr"] + i * 8
        slot_off = sec["offset"] + i * 8

        if slot_off + 8 > len(data):
            break

        ptr = u64(slot_off)

        if not ptr:
            continue

        name = vm_cstr(ptr)

        if name:
            selector_slots[name].append(slot_vm)


# ------------------------------------------------------------
# Classrefs
# ------------------------------------------------------------

classref_targets = {}

classref_sections = [
    sec
    for (segname, sectname), sec in sections.items()
    if sectname == "__objc_classrefs"
]

for sec in classref_sections:

    count = sec["size"] // 8

    for i in range(count):

        slot_vm = sec["addr"] + i * 8
        slot_off = sec["offset"] + i * 8

        if slot_off + 8 > len(data):
            break

        ptr = u64(slot_off)

        if ptr == GK_CLASS:

            classref_targets[
                slot_vm
            ] = "CLASS:GkOEznX"

        elif ptr == LH_CLASS:

            classref_targets[
                slot_vm
            ] = "CLASS:LHxbzDSewNaAjVygv"


print("=== CLASSREFS ===")

if classref_targets:

    for slot, label in sorted(
        classref_targets.items()
    ):
        print(
            f"0x{slot:x} -> {label}"
        )

else:

    print("No direct classrefs found")

print()


# ------------------------------------------------------------
# Interesting selector refs
# ------------------------------------------------------------

target_slots = dict(classref_targets)


print("=== INTERESTING SELREFS ===")

selector_count = 0

for name in sorted(INTERESTING_SELECTORS):

    slots = selector_slots.get(name, [])

    for slot in slots:

        selector_count += 1

        label = "SEL:" + name

        target_slots[slot] = label

        print(
            f"0x{slot:x} -> {name}"
        )

if selector_count == 0:
    print("No result")

print()


# ------------------------------------------------------------
# LC_FUNCTION_STARTS
# ------------------------------------------------------------

function_starts = []


def read_uleb(buf, pos, end):

    result = 0
    shift = 0

    while pos < end:

        b = buf[pos]
        pos += 1

        result |= (b & 0x7F) << shift

        if not (b & 0x80):
            return result, pos

        shift += 7

    return None, pos


if function_starts_info:

    fs_off, fs_size = function_starts_info

    pos = fs_off
    end = fs_off + fs_size

    current = 0

    text_segment = None

    for seg in segments:

        if seg["name"] == "__TEXT":
            text_segment = seg
            break

    base = (
        text_segment["vmaddr"]
        if text_segment
        else 0
    )

    while pos < end:

        delta, pos = read_uleb(
            data,
            pos,
            end,
        )

        if delta is None:
            break

        if delta == 0:
            break

        current += delta

        function_starts.append(
            base + current
        )


function_starts = sorted(
    set(function_starts)
)


def containing_function(addr):

    if not function_starts:

        return (
            addr,
            addr + 0x200,
        )

    i = (
        bisect.bisect_right(
            function_starts,
            addr,
        )
        - 1
    )

    if i < 0:

        return (
            addr,
            addr + 0x200,
        )

    start = function_starts[i]

    if i + 1 < len(function_starts):

        end = function_starts[i + 1]

    else:

        end = start + 0x400

    # Guard against pathological gaps
    if end - start > 0x4000:
        end = start + 0x4000

    return start, end


print("=== FUNCTION STARTS ===")
print(
    f"decoded = {len(function_starts):,}"
)
print()


# ------------------------------------------------------------
# ARM64 helpers
# ------------------------------------------------------------

def decode_adrp(word, pc):

    # ADRP mask
    if (word & 0x9F000000) != 0x90000000:
        return None

    rd = word & 0x1F

    immlo = (
        (word >> 29)
        & 0x3
    )

    immhi = (
        (word >> 5)
        & 0x7FFFF
    )

    imm21 = (
        (immhi << 2)
        | immlo
    )

    imm21 = sign_extend(
        imm21,
        21,
    )

    target_page = (
        (pc & ~0xFFF)
        + (imm21 << 12)
    )

    return (
        rd,
        target_page,
    )


def decode_ldr64_unsigned(word):

    # LDR Xt, [Xn, #imm]
    if (
        word & 0xFFC00000
    ) != 0xF9400000:

        return None

    rt = word & 0x1F

    rn = (
        (word >> 5)
        & 0x1F
    )

    imm12 = (
        (word >> 10)
        & 0xFFF
    )

    return (
        rt,
        rn,
        imm12 * 8,
    )


# ------------------------------------------------------------
# FAST xref scan
#
# Key optimization:
#
# ADRP's top byte after mask must be one of:
#   0x90 0xB0 0xD0 0xF0
#
# Instead of:
#
#   for every 4-byte instruction:
#
# we let Python's regex engine find only bytes that could end
# an ADRP instruction, then verify the complete instruction.
#
# ------------------------------------------------------------

print("=== FAST XREF SCAN ===")
print(
    f"interesting slots = {len(target_slots)}"
)
print(
    "strategy          = ADRP byte prefilter + LDR verification"
)
print()


adrp_tail_pattern = re.compile(
    b"[\x90\xb0\xd0\xf0]"
)

hits = []

progress = Progress(
    total=len(text_bytes),
    label="Xref scan",
)

last_progress_pos = 0
candidate_adrp = 0
verified_adrp = 0


for match in adrp_tail_pattern.finditer(text_bytes):

    tail_pos = match.start()

    # ADRP instruction is four bytes.
    # The matched high byte must be byte #3.
    if tail_pos < 3:
        continue

    inst_off = tail_pos - 3

    if inst_off & 3:
        continue

    candidate_adrp += 1

    # Update every ~128 KB instead of on every match.
    if (
        inst_off
        - last_progress_pos
        >= 0x20000
    ):

        progress.update(inst_off)

        last_progress_pos = inst_off

    if inst_off + 4 > len(text_bytes):
        continue

    word = struct.unpack_from(
        "<I",
        text_bytes,
        inst_off,
    )[0]

    pc = TEXT_ADDR + inst_off

    decoded = decode_adrp(
        word,
        pc,
    )

    if not decoded:
        continue

    verified_adrp += 1

    base_reg, page = decoded

    # Compiler usually loads the selref/classref
    # within the next few instructions.
    for step in range(1, 6):

        next_off = (
            inst_off
            + step * 4
        )

        if (
            next_off + 4
            > len(text_bytes)
        ):
            break

        next_word = struct.unpack_from(
            "<I",
            text_bytes,
            next_off,
        )[0]

        decoded_ldr = (
            decode_ldr64_unsigned(
                next_word
            )
        )

        if not decoded_ldr:
            continue

        rt, rn, displacement = (
            decoded_ldr
        )

        if rn != base_reg:
            continue

        target = (
            page
            + displacement
        )

        label = target_slots.get(
            target
        )

        if label is None:
            continue

        hits.append({
            "adrp": pc,
            "load": TEXT_ADDR + next_off,
            "slot": target,
            "label": label,
        })


progress.finish()


print()
print(
    f"ADRP byte candidates = "
    f"{candidate_adrp:,}"
)
print(
    f"verified ADRP        = "
    f"{verified_adrp:,}"
)
print(
    f"interesting hits     = "
    f"{len(hits):,}"
)
print()


# ------------------------------------------------------------
# Aggregate by containing function
# ------------------------------------------------------------

functions = {}


for hit in hits:

    start, end = containing_function(
        hit["adrp"]
    )

    info = functions.setdefault(
        start,
        {
            "start": start,
            "end": end,
            "hits": [],
            "labels": set(),
        },
    )

    info["hits"].append(hit)

    info["labels"].add(
        hit["label"]
    )


def score_function(info):

    score = 0

    labels = info["labels"]

    for label in labels:

        score += WEIGHTS.get(
            label,
            1,
        )

    # Cross-layer combinations are especially interesting.
    if "CLASS:GkOEznX" in labels:

        if any(
            x.startswith("SEL:")
            for x in labels
        ):
            score += 8

    if (
        "CLASS:LHxbzDSewNaAjVygv"
        in labels
    ):

        score += 7

    # More distinct references means this function is more
    # likely to orchestrate/build something.
    score += (
        max(
            0,
            len(labels) - 1,
        )
        * 2
    )

    return score


ranked = sorted(
    functions.values(),
    key=lambda x: (
        -score_function(x),
        x["start"],
    ),
)


print("=== SUMMARY ===")
print(
    f"candidate functions = "
    f"{len(ranked):,}"
)
print()


if not ranked:

    print("No result")
    raise SystemExit(0)


# ------------------------------------------------------------
# Ranked candidate list
# ------------------------------------------------------------

print("=== RANKED CANDIDATES ===")
print()


for index, info in enumerate(
    ranked[:40],
    1,
):

    start = info["start"]

    score = score_function(
        info
    )

    names = method_names.get(
        start,
        [],
    )

    print(
        f"[{index:02d}] "
        f"function 0x{start:x} "
        f"score={score}"
    )

    if names:

        for name in names:
            print(
                f"     objc: {name}"
            )

    else:

        print(
            "     objc: "
            "<unknown/non-ObjC>"
        )

    for label in sorted(
        info["labels"]
    ):

        print(
            f"     ref : {label}"
        )

    print(
        "     xrefs:"
    )

    for hit in sorted(
        info["hits"],
        key=lambda x: x["adrp"],
    ):

        print(
            f"       "
            f"0x{hit['adrp']:x} "
            f"-> "
            f"0x{hit['slot']:x} "
            f"{hit['label']}"
        )

    print()


# ------------------------------------------------------------
# Disassemble only high-value candidates
#
# This is intentionally small. Capstone does NOT scan the entire
# ~12 MB __text anymore.
# ------------------------------------------------------------

md = Cs(
    CS_ARCH_ARM64,
    CS_MODE_ARM,
)


print(
    "=== TOP CANDIDATE DISASSEMBLY ==="
)


for index, info in enumerate(
    ranked[:10],
    1,
):

    start = info["start"]
    end = info["end"]

    # Do not dump gigantic functions.
    show_end = min(
        end,
        start + 0x400,
    )

    file_off = vm_to_off(start)

    if file_off is None:
        continue

    size = (
        show_end
        - start
    )

    blob = data[
        file_off:
        file_off + size
    ]

    print()
    print(
        "=" * 78
    )

    print(
        f"CANDIDATE {index}"
    )

    print(
        f"function = 0x{start:x}"
    )

    print(
        f"score    = "
        f"{score_function(info)}"
    )

    names = method_names.get(
        start,
        [],
    )

    if names:

        for name in names:
            print(name)

    print(
        "-" * 78
    )

    hit_by_address = {}

    for hit in info["hits"]:

        hit_by_address[
            hit["adrp"]
        ] = (
            hit["label"]
        )

        hit_by_address[
            hit["load"]
        ] = (
            hit["label"]
        )

    try:

        for ins in md.disasm(
            blob,
            start,
        ):

            label = hit_by_address.get(
                ins.address
            )

            if label:

                marker = ">>"

                suffix = (
                    f"    ; {label}"
                )

            else:

                marker = "  "
                suffix = ""

            print(
                f"{marker} "
                f"0x{ins.address:08x}: "
                f"{ins.mnemonic:<8} "
                f"{ins.op_str}"
                f"{suffix}"
            )

    except Exception as e:

        print(
            f"<disassembly error: {e}>"
        )


print()
print("=== END ===")
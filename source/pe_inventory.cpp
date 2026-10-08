#include "manifest.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <Zydis.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace channel_expand {
namespace {
bool Fits(std::size_t off, std::size_t len, std::size_t size) { return off <= size && len <= size - off; }
template<class T> T Pod(const std::vector<std::uint8_t>& b, std::size_t off) {
    if (!Fits(off, sizeof(T), b.size())) throw std::runtime_error("truncated PE field");
    T v{}; std::memcpy(&v, b.data() + off, sizeof(T)); return v;
}
std::string Hex(std::uint64_t v) { std::ostringstream s; s << "0x" << std::hex << std::uppercase << v; return s.str(); }
std::string BytesHex(const std::uint8_t* p, std::size_t n) {
    std::ostringstream s; s << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < n; ++i) { if (i) s << ' '; s << std::setw(2) << static_cast<unsigned>(p[i]); } return s.str();
}
std::string Quote(const std::string& t) {
    std::ostringstream s; s << '"';
    for (unsigned char c : t) {
        if (c == '"' || c == '\\') s << '\\' << c;
        else if (c < 32) s << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
        else s << c;
    } s << '"'; return s.str();
}
struct Cng {
    BCRYPT_ALG_HANDLE alg{}; BCRYPT_HASH_HANDLE hash{}; std::vector<std::uint8_t> object;
    ~Cng() { if (hash) BCryptDestroyHash(hash); if (alg) BCryptCloseAlgorithmProvider(alg, 0); }
};
std::string Sha256(const std::vector<std::uint8_t>& b) {
    Cng c; ULONG size{}, used{}; std::array<std::uint8_t, 32> digest{};
    if (b.size() > ULONG_MAX || BCryptOpenAlgorithmProvider(&c.alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(c.alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&size), sizeof(size), &used, 0) < 0) throw std::runtime_error("SHA256 init failed");
    c.object.resize(size);
    if (BCryptCreateHash(c.alg, &c.hash, c.object.data(), size, nullptr, 0, 0) < 0 ||
        BCryptHashData(c.hash, const_cast<PUCHAR>(b.data()), static_cast<ULONG>(b.size()), 0) < 0 ||
        BCryptFinishHash(c.hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) throw std::runtime_error("SHA256 failed");
    auto s = BytesHex(digest.data(), digest.size()); s.erase(std::remove(s.begin(), s.end(), ' '), s.end()); return s;
}
std::uint32_t ResolveRoot(const PeImageView& image, std::uint32_t begin, std::uint32_t unwind, bool& valid) {
    std::set<std::uint32_t> seen; valid = false;
    for (unsigned depth = 0; depth < 64; ++depth) {
        if (!seen.insert(unwind).second) return begin;
        const auto* h = image.rva_ptr(unwind, 4); if (!h || (h[0] & 7) != 1) return begin;
        const auto flags = h[0] >> 3;
        if (!(flags & UNW_FLAG_CHAININFO)) { valid = true; return begin; }
        if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) return begin;
        const std::uint64_t code_bytes = static_cast<std::uint64_t>((h[2] + 1u) & ~1u) * 2ull;
        const std::uint64_t tail = static_cast<std::uint64_t>(unwind) + 4ull + code_bytes;
        if (tail > UINT32_MAX) return begin;
        const auto* p = image.rva_ptr(static_cast<std::uint32_t>(tail), sizeof(RUNTIME_FUNCTION)); if (!p) return begin;
        RUNTIME_FUNCTION parent{}; std::memcpy(&parent, p, sizeof(parent));
        if (parent.BeginAddress >= parent.EndAddress || !image.rva_ptr(parent.BeginAddress, parent.EndAddress - parent.BeginAddress)) return begin;
        begin = parent.BeginAddress; unwind = parent.UnwindData;
    } return begin;
}
std::string TargetKind(std::uint64_t t) {
    if (t >= kChannelsRva && t < kChannelsEndRva) return "channel_array";
    if (t >= kActiveRva && t < kActiveRva + 4 + kOldCapacity * 2) return "active_table";
    if (t == kTotalRva) return "total_channels";
    if (t == kChannelsEndRva) return "adjacent_global";
    return {};
}
void ScanRange(const PeImageView& image, BuildManifest& m, std::uint32_t begin, std::uint32_t end, std::uint32_t root, bool bounded) {
    ZydisDecoder decoder; ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter; ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    std::vector<std::uint32_t> pending{begin}; std::set<std::uint32_t> visited;
    while (!pending.empty()) {
    auto cursor = pending.back(); pending.pop_back();
    while (cursor < end && visited.insert(cursor).second) {
        const auto n = static_cast<std::size_t>(end - cursor); const auto* code = image.rva_ptr(cursor, n);
        if (!code) { m.decode_issues.push_back({cursor, begin, "range not backed by file"}); return; }
        ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, n, &ins, ops))) {
            if (bounded) { m.decode_issues.push_back({cursor, begin, "decode failed on reachable instruction"}); break; }
            ++cursor; continue; // gap 内的候选不具有补丁资格，不跨失败字节生成语义匹配。
        }
        char text[256]{}; ZydisFormatterFormatInstruction(&formatter, &ins, ops, ins.operand_count_visible, text, sizeof(text), image.preferred_base + cursor, nullptr);
        const auto add = [&](const std::string& kind, std::uint32_t target) {
            m.references.push_back({cursor, target, begin, root, kind, text, BytesHex(code, ins.length), bounded ? "decoded_unwind_interval" : "unwind_gap_candidate"});
        };
        for (std::uint8_t i = 0; i < ins.operand_count_visible; ++i) {
            const auto& op = ops[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP) {
                const auto t = static_cast<std::int64_t>(cursor) + ins.length + op.mem.disp.value;
                if (t >= 0 && t < image.image_size) { const auto kind = TargetKind(static_cast<std::uint64_t>(t)); if (!kind.empty()) add(kind, static_cast<std::uint32_t>(t)); }
            }
            // MSVC also emits [image-base-register + scaled-index + member-RVA].
            // These are candidates until the base register's definition is traced.
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base != ZYDIS_REGISTER_RIP && op.mem.disp.has_displacement && op.mem.disp.value >= 0) {
                const auto kind = TargetKind(static_cast<std::uint64_t>(op.mem.disp.value));
                if (!kind.empty()) add("image_base_offset_candidate_"+kind,static_cast<std::uint32_t>(op.mem.disp.value));
            }
            if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
            if (op.imm.is_relative) {
                const auto t = static_cast<std::int64_t>(cursor) + ins.length + op.imm.value.s;
                if (t == 0x2C110 && (ins.mnemonic == ZYDIS_MNEMONIC_CALL || ins.mnemonic == ZYDIS_MNEMONIC_JMP)) add("snapshot_call", 0x2C110);
                if (t == 0x4A1B0 && (ins.mnemonic == ZYDIS_MNEMONIC_CALL || ins.mnemonic == ZYDIS_MNEMONIC_JMP)) add("snapshot_owner_call", 0x4A1B0);
                if (t == 0x4A7F0 && (ins.mnemonic == ZYDIS_MNEMONIC_CALL || ins.mnemonic == ZYDIS_MNEMONIC_JMP)) add("paint_consumer_call", 0x4A7F0);
            } else {
                const auto v = op.imm.value.u;
                if (v >= image.preferred_base && v - image.preferred_base < image.image_size) {
                    const auto kind = TargetKind(v - image.preferred_base); if (!kind.empty()) add("absolute_" + kind, static_cast<std::uint32_t>(v - image.preferred_base));
                }
                if (begin >= 0x2C000 && begin < 0x4F000 && (v == 128 || v == 256 || v == 384 || v == 388 || v == 392)) add("capacity_or_layout_candidate", static_cast<std::uint32_t>(v));
                if (begin >= 0x2C000 && begin < 0x4F000 && v==kOldCapacity*kChannelStride)
                    add("fixed_channel_storage_byte_count_candidate",static_cast<std::uint32_t>(v));
            }
        }
        if (bounded) {
            // 只沿控制流访问有展开记录的代码，避免把跳转后的内嵌数据误解码成指令。
            if (ins.meta.category == ZYDIS_CATEGORY_COND_BR || ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[0].imm.is_relative) {
                    const auto branch = static_cast<std::int64_t>(cursor) + ins.length + ops[0].imm.value.s;
                    if (branch >= begin && branch < end) pending.push_back(static_cast<std::uint32_t>(branch));
                } else if (begin >= 0x2C000 && begin < 0x4F000) add("indirect_branch_requires_resolution", 0);
                if (ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR) break;
            }
            if (ins.meta.category == ZYDIS_CATEGORY_RET || ins.mnemonic == ZYDIS_MNEMONIC_INT3) break;
        }
        cursor += ins.length;
    }
    }
}
}
const std::uint8_t* PeImageView::rva_ptr(std::uint32_t rva, std::size_t len) const noexcept {
    if (!Fits(rva, len, image_size)) return nullptr;
    if (Fits(rva, len, headers_size) && Fits(rva, len, bytes.size())) return bytes.data() + rva;
    for (const auto& s : sections) if (rva >= s.rva) {
        const auto d = rva - s.rva;
        if (Fits(d, len, s.raw_size) && Fits(static_cast<std::size_t>(s.offset) + d, len, bytes.size())) return bytes.data() + s.offset + d;
    } return nullptr;
}
bool ParsePe(std::vector<std::uint8_t> bytes, PeImageView& out, std::string& reason) {
    reason.clear();
    try {
        const auto dos = Pod<IMAGE_DOS_HEADER>(bytes, 0);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) throw std::runtime_error("bad DOS header");
        const auto nt = static_cast<std::size_t>(dos.e_lfanew);
        if (Pod<DWORD>(bytes, nt) != IMAGE_NT_SIGNATURE) throw std::runtime_error("bad NT signature");
        const auto f = Pod<IMAGE_FILE_HEADER>(bytes, nt + 4);
        if (f.Machine != IMAGE_FILE_MACHINE_AMD64 || !f.NumberOfSections || f.NumberOfSections > 96 || f.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) throw std::runtime_error("unsupported machine/sections");
        const auto opt = Pod<IMAGE_OPTIONAL_HEADER64>(bytes, nt + 24);
        if (opt.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || opt.NumberOfRvaAndSizes < 16 || !opt.SizeOfImage || !opt.SizeOfHeaders || opt.SizeOfHeaders > opt.SizeOfImage || opt.SizeOfHeaders > bytes.size()) throw std::runtime_error("bad optional header");
        const auto table = nt + 24 + f.SizeOfOptionalHeader;
        if (!Fits(table, static_cast<std::size_t>(f.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), opt.SizeOfHeaders)) throw std::runtime_error("section headers outside SizeOfHeaders");
        PeImageView image; image.bytes = std::move(bytes); image.preferred_base = opt.ImageBase;
        image.image_size = opt.SizeOfImage; image.headers_size = opt.SizeOfHeaders; image.timestamp = f.TimeDateStamp; image.entry = opt.AddressOfEntryPoint;
        image.reloc_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress; image.reloc_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        bool code = false;
        for (WORD i = 0; i < f.NumberOfSections; ++i) {
            const auto s = Pod<IMAGE_SECTION_HEADER>(image.bytes, table + i * sizeof(IMAGE_SECTION_HEADER));
            if (s.VirtualAddress < image.headers_size || !Fits(s.VirtualAddress, std::max(s.Misc.VirtualSize, s.SizeOfRawData), image.image_size) ||
                (s.SizeOfRawData && (s.PointerToRawData < image.headers_size || !Fits(s.PointerToRawData, s.SizeOfRawData, image.bytes.size())))) throw std::runtime_error("section bounds invalid");
            std::size_t n = 0; while (n < 8 && s.Name[n]) ++n;
            image.sections.push_back({s.VirtualAddress, s.Misc.VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics, std::string(reinterpret_cast<const char*>(s.Name), n)});
            code = code || ((s.Characteristics & IMAGE_SCN_MEM_EXECUTE) && s.SizeOfRawData);
        }
        std::sort(image.sections.begin(), image.sections.end(), [](const auto& a, const auto& b) { return a.rva < b.rva; });
        for (std::size_t i = 1; i < image.sections.size(); ++i) {
            const auto& p = image.sections[i-1]; if (static_cast<std::uint64_t>(p.rva) + std::max(p.virtual_size, p.raw_size) > image.sections[i].rva) throw std::runtime_error("overlapping virtual sections");
        }
        if (!code) throw std::runtime_error("no executable section");
        const auto ex = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!ex.Size || ex.Size % sizeof(RUNTIME_FUNCTION) || !image.rva_ptr(ex.VirtualAddress, ex.Size)) throw std::runtime_error("bad exception directory");
        for (std::uint32_t pos = 0; pos < ex.Size; pos += sizeof(RUNTIME_FUNCTION)) {
            RUNTIME_FUNCTION fun{}; std::memcpy(&fun, image.rva_ptr(ex.VirtualAddress + pos, sizeof(fun)), sizeof(fun));
            if (fun.BeginAddress >= fun.EndAddress || !image.rva_ptr(fun.BeginAddress, fun.EndAddress - fun.BeginAddress)) throw std::runtime_error("bad function bounds");
            const auto sec = std::find_if(image.sections.begin(), image.sections.end(), [&](const auto& s) { return (s.flags & IMAGE_SCN_MEM_EXECUTE) && fun.BeginAddress >= s.rva && Fits(fun.BeginAddress - s.rva, fun.EndAddress - fun.BeginAddress, s.raw_size); });
            if (sec == image.sections.end()) throw std::runtime_error("function outside executable section");
            bool valid{}; const auto root = ResolveRoot(image, fun.BeginAddress, fun.UnwindData, valid);
            image.functions.push_back({fun.BeginAddress, fun.EndAddress, fun.UnwindData, root, valid});
        }
        std::sort(image.functions.begin(), image.functions.end(), [](const auto& a, const auto& b) { return a.begin < b.begin; });
        for (std::size_t i = 1; i < image.functions.size(); ++i) if (image.functions[i-1].end > image.functions[i].begin) throw std::runtime_error("overlapping function intervals");
        out = std::move(image); return true;
    } catch (const std::exception& e) { reason = e.what(); return false; }
}
bool VerifyKnownChannelLeaves(const PeImageView& image,std::string& reason) {
    // Exact known-build, independently bounded leaf bodies. No .pdata means no
    // unwind record, not an invitation to infer a function from a gap scan.
    struct Leaf { std::uint32_t start,length,rip,target; const char* sha; };
    const std::array<Leaf,2> leaves{{
        {0x8B00,0x355,0x8B05,kChannelsRva+0xEC,"C257CED405B06947051505F3D59C2F76DB9ECE282E6DF03597D6F2287CCF062C"},
        {0x2F160,0x53,0x2F18B,kChannelsRva+0x128,"2CF4C08EA40A4F71A455B6F9ECE3D958C5CBFC6C7CE77282F221355C13229ADD"}}};
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    for (const auto& leaf:leaves) {
        const auto* bytes=image.rva_ptr(leaf.start,leaf.length);
        if (!bytes || Sha256(std::vector<std::uint8_t>(bytes,bytes+leaf.length))!=leaf.sha) {
            reason="known channel leaf body fingerprint differs"; return false;
        }
        std::vector<std::uint32_t> starts,branches; std::uint32_t offset=0,rip_count=0;
        while (offset<leaf.length) {
            ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes+offset,leaf.length-offset,&ins,ops)) ||
                ins.mnemonic==ZYDIS_MNEMONIC_CALL || (ins.mnemonic==ZYDIS_MNEMONIC_RET && offset+ins.length!=leaf.length)) {
                reason="channel leaf has an invalid boundary or external call"; return false;
            }
            starts.push_back(leaf.start+offset);
            for (std::uint8_t i=0;i<ins.operand_count_visible;++i) {
                if (ops[i].type==ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
                    ZyanU64 target{};
                    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins,&ops[i],leaf.start+offset,&target)) ||
                        target<leaf.start || target>=leaf.start+leaf.length) { reason="channel leaf branches outside bounded body"; return false; }
                    branches.push_back(static_cast<std::uint32_t>(target));
                }
                if (ops[i].type==ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base==ZYDIS_REGISTER_RIP) {
                    ZyanU64 target{};
                    if (leaf.start+offset!=leaf.rip || !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins,&ops[i],leaf.start+offset,&target)) || target!=leaf.target) {
                        reason="unexpected channel leaf RIP reference"; return false;
                    }
                    ++rip_count;
                }
            }
            offset+=ins.length;
        }
        if (offset!=leaf.length || bytes[leaf.length-1]!=0xC3 || rip_count!=1 ||
            std::any_of(branches.begin(),branches.end(),[&](std::uint32_t target){return !std::binary_search(starts.begin(),starts.end(),target);})) {
            reason="channel leaf branch targets or terminal return invalid"; return false;
        }
    }
    reason.clear(); return true;
}
InventoryResult InspectEngine(const std::filesystem::path& path) {
    InventoryResult r; std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) { r.reason = "cannot open file read-only"; return r; }
    const auto len = file.tellg(); if (len < 0 || len > 256 * 1024 * 1024) { r.reason = "invalid file size"; return r; }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(len)); file.seekg(0);
    if (!bytes.empty() && !file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) { r.reason = "short file read"; return r; }
    r.manifest.sha256 = Sha256(bytes);
    if (!ParsePe(std::move(bytes), r.image, r.reason)) return r;
    r.parsed = true; auto& m = r.manifest; const auto& image = r.image; m.supported = m.sha256 == kExpectedSha;
    if (!m.supported) m.unresolved.push_back("engine SHA256 does not match the approved Build");
    for (const auto& f : image.functions) { if (!f.chain_valid) m.decode_issues.push_back({f.begin, f.begin, "unwind chain invalid or unsupported by this parser"}); ScanRange(image, m, f.begin, f.end, f.root, true); }
    for (const auto& s : image.sections) {
        if (!(s.flags & IMAGE_SCN_MEM_EXECUTE)) continue;
        auto cursor = s.rva; const auto end = s.rva + std::min(s.virtual_size, s.raw_size);
        for (const auto& f : image.functions) {
            if (f.begin < s.rva || f.begin >= end) continue;
            if (cursor < f.begin) ScanRange(image, m, cursor, f.begin, 0, false);
            cursor = f.end;
        } if (cursor < end) ScanRange(image, m, cursor, end, 0, false);
    }
    std::uint32_t cursor = 0;
    while (cursor < image.reloc_size) {
        const auto* p = image.rva_ptr(image.reloc_rva + cursor, sizeof(IMAGE_BASE_RELOCATION));
        if (!p) { m.decode_issues.push_back({image.reloc_rva + cursor, 0, "truncated relocation block"}); break; }
        IMAGE_BASE_RELOCATION block{}; std::memcpy(&block, p, sizeof(block));
        if (block.SizeOfBlock < sizeof(block) || (block.SizeOfBlock - sizeof(block)) % 2 || block.SizeOfBlock > image.reloc_size - cursor || !image.rva_ptr(image.reloc_rva + cursor, block.SizeOfBlock)) { m.decode_issues.push_back({image.reloc_rva + cursor, 0, "invalid relocation block"}); break; }
        for (std::uint32_t pos = sizeof(block); pos < block.SizeOfBlock; pos += 2) {
            WORD e{}; std::memcpy(&e, image.rva_ptr(image.reloc_rva + cursor + pos, 2), 2); if ((e >> 12) != IMAGE_REL_BASED_DIR64) continue;
            const auto address = static_cast<std::uint64_t>(block.VirtualAddress) + (e & 0xFFF); if (address > UINT32_MAX) continue;
            const auto location = static_cast<std::uint32_t>(address); const auto* ptr = image.rva_ptr(location, 8); if (!ptr) continue;
            std::uint64_t va{}; std::memcpy(&va, ptr, 8); if (va < image.preferred_base || va - image.preferred_base >= image.image_size) continue;
            const auto kind = TargetKind(va - image.preferred_base);
            if (!kind.empty()) m.references.push_back({location, static_cast<std::uint32_t>(va - image.preferred_base), 0, 0, "relocated_pointer_" + kind, "DIR64", BytesHex(ptr, 8), "relocation_candidate"});
        } cursor += block.SizeOfBlock;
    }
    if (m.supported) {
        std::string leaf_reason;
        if (VerifyKnownChannelLeaves(image,leaf_reason)) {
            for (auto& ref:m.references) {
                if (ref.instruction==0x8B05 || ref.instruction==0x2F18B) {
                    ref.root=ref.range_begin=ref.instruction==0x8B05?0x8B00:0x2F160;
                    ref.confidence="verified_channel_leaf";
                }
            }
            // This leaf is below the broad audio candidate scan window. Record
            // its real loop bound only after the complete body is verified.
            m.references.push_back({0x8B00,128,0x8B00,0x8B00,"capacity_or_layout_candidate",
                "mov ecx,128; coordinate initializer loop bound",BytesHex(image.rva_ptr(0x8B00,5),5),"verified_channel_leaf"});
        } else m.decode_issues.push_back({0x8B00,0x8B00,leaf_reason});
    }
    std::sort(m.references.begin(), m.references.end(), [](const auto& a, const auto& b) { return a.instruction < b.instruction; });
    m.unresolved = {"direct and indirect channel references need semantic adapter mapping", "snapshot consumers retain 128-entry layout", "mix sorting/scratch capacity remains 128", "quiescence and retained mixer channel pointers unproven"};
    if (!m.supported) m.unresolved.push_back("unsupported Build");
    m.complete = false; return r;
}
bool ValidateManifest(const BuildManifest& m, const PeImageView& image, std::string& reason) {
    if (!m.supported || m.sha256 != kExpectedSha) { reason = "unsupported Build"; return false; }
    if (!m.complete || !m.unresolved.empty() || !m.decode_issues.empty()) { reason = "incomplete semantic adapters"; return false; }
    const bool mapped_array = std::any_of(image.sections.begin(), image.sections.end(), [](const auto& s) {
        return (s.flags & IMAGE_SCN_MEM_WRITE) && kChannelsRva >= s.rva &&
            Fits(kChannelsRva-s.rva,kOldCapacity*kChannelStride,s.virtual_size);
    });
    // The original channel array is in zero-initialized .data (no file bytes).
    if (m.references.empty() || !mapped_array) { reason = "missing array section mapping"; return false; }
    reason = "adapter verification not implemented; installation disabled"; return false;
}
std::string InventoryJson(const InventoryResult& r) {
    std::ostringstream s; const auto& m = r.manifest;
    s << "{\n\"schema\":1,\n\"parsed\":" << (r.parsed ? "true" : "false") << ",\n\"supported\":" << (m.supported ? "true" : "false") << ",\n\"complete\":false,\n\"sha256\":" << Quote(m.sha256) << ",\n\"reason\":" << Quote(r.reason) << ",\n\"target_capacity\":512,\n\"dynamic_capacity\":64,\n\"static_capacity\":448,\n\"references\":[\n";
    for (std::size_t i = 0; i < m.references.size(); ++i) {
        const auto& v = m.references[i]; s << "{\"rva\":" << Quote(Hex(v.instruction)) << ",\"target\":" << Quote(Hex(v.target)) << ",\"interval\":" << Quote(Hex(v.range_begin)) << ",\"root\":" << Quote(Hex(v.root)) << ",\"kind\":" << Quote(v.kind) << ",\"instruction\":" << Quote(v.instruction_text) << ",\"bytes\":" << Quote(v.original_bytes) << ",\"confidence\":" << Quote(v.confidence) << "}" << (i+1 == m.references.size() ? "\n" : ",\n");
    }
    s << "],\n\"decode_issues\":[\n";
    for (std::size_t i = 0; i < m.decode_issues.size(); ++i) { const auto& v = m.decode_issues[i]; s << "{\"rva\":" << Quote(Hex(v.rva)) << ",\"interval\":" << Quote(Hex(v.range_begin)) << ",\"reason\":" << Quote(v.reason) << "}" << (i+1 == m.decode_issues.size() ? "\n" : ",\n"); }
    s << "],\n\"unresolved\":["; for (std::size_t i = 0; i < m.unresolved.size(); ++i) { if (i) s << ','; s << Quote(m.unresolved[i]); } s << "]\n}\n"; return s.str();
}
bool RunPeSelfChecks(std::string& reason) {
    PeImageView image; std::string why;
    for (const auto n : {0u, 2u, 63u, 64u, 512u}) if (ParsePe(std::vector<std::uint8_t>(n), image, why)) { reason = "garbage/truncated PE accepted"; return false; }
    std::vector<std::uint8_t> bad(512); IMAGE_DOS_HEADER d{}; d.e_magic = IMAGE_DOS_SIGNATURE; d.e_lfanew = 0x7FFFFFFF; std::memcpy(bad.data(), &d, sizeof(d));
    if (ParsePe(bad, image, why)) { reason = "out-of-bounds NT offset accepted"; return false; }
    d.e_lfanew = -1; std::memcpy(bad.data(), &d, sizeof(d)); if (ParsePe(bad, image, why)) { reason = "negative NT offset accepted"; return false; }
    if (Sha256({}) != "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855") { reason = "SHA256 mismatch"; return false; }
    if (image.rva_ptr(UINT32_MAX, SIZE_MAX)) { reason = "overflowing RVA accepted"; return false; }
    BuildManifest m; m.supported = true; m.sha256 = kExpectedSha; m.complete = true;
    if (ValidateManifest(m, image, why)) { reason = "empty manifest enabled install"; return false; }
    reason.clear(); return true;
}
}

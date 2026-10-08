#include "manifest.hpp"
#include <windows.h>
#include <cstring>
#include <algorithm>
#include <map>

namespace channel_expand {
namespace {
bool ReadBytes(std::uintptr_t address,void* data,std::size_t size) {
    SIZE_T copied{};
    return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),data,size,&copied) && copied==size;
}
DWORD Protection(std::uintptr_t address) {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(reinterpret_cast<const void*>(address),&info,sizeof(info))==sizeof(info)?info.Protect:0;
}
bool Executable(DWORD protection) {
    const auto access=protection&0xFF;
    return access==PAGE_EXECUTE || access==PAGE_EXECUTE_READ || access==PAGE_EXECUTE_READWRITE || access==PAGE_EXECUTE_WRITECOPY;
}
DWORD Writable(DWORD protection) {
    const auto modifiers=protection&(PAGE_NOCACHE|PAGE_WRITECOMBINE);
    // Preserve CFG target metadata when changing an already executable page.
    return (Executable(protection)?PAGE_EXECUTE_READWRITE|PAGE_TARGETS_NO_UPDATE:PAGE_READWRITE)|modifiers;
}
DWORD RestoreFlags(DWORD protection) {
    return protection|(Executable(protection)?PAGE_TARGETS_NO_UPDATE:0);
}
bool ApplyInternal(const std::vector<MemoryPatch>& patches,std::string& reason,int fail_after_write,int fail_after_protect) {
    if (patches.empty()) { reason="empty patch transaction"; return false; }
    SYSTEM_INFO info{}; GetSystemInfo(&info); const auto page_size=static_cast<std::uintptr_t>(info.dwPageSize);
    struct Page { std::uintptr_t address; DWORD original; bool changed{}; };
    std::vector<const MemoryPatch*> ordered;
    for (const auto& patch:patches) {
        if (!patch.address || patch.expected.empty() || patch.expected.size()!=patch.replacement.size() ||
            patch.expected.size()>UINTPTR_MAX-patch.address) { reason="invalid patch range or lengths"; return false; }
        ordered.push_back(&patch);
    }
    std::sort(ordered.begin(),ordered.end(),[](const auto* a,const auto* b) { return a->address<b->address; });
    for (std::size_t i=1;i<ordered.size();++i) {
        if (ordered[i]->address<ordered[i-1]->address+ordered[i-1]->expected.size()) { reason="overlapping patch ranges"; return false; }
    }
    std::map<std::uintptr_t,DWORD> unique_pages;
    for (const auto* patch:ordered) {
        const auto end=patch->address+patch->expected.size();
        for (auto address=patch->address/page_size*page_size;address<end;) {
            MEMORY_BASIC_INFORMATION memory{};
            if (VirtualQuery(reinterpret_cast<const void*>(address),&memory,sizeof(memory))!=sizeof(memory) ||
                memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)) || !(memory.Protect&0xFF)) {
                reason="patch page not committed or is inaccessible"; return false;
            }
            unique_pages.emplace(address,memory.Protect);
            if (address>UINTPTR_MAX-page_size) { reason="patch page arithmetic overflow"; return false; }
            address+=page_size;
        }
    }
    std::vector<Page> pages; for (const auto& page:unique_pages) pages.push_back({page.first,page.second,false});
    std::vector<std::vector<std::uint8_t>> buffers;
    for (const auto* patch:ordered) {
        buffers.emplace_back(patch->expected.size());
        if (!ReadBytes(patch->address,buffers.back().data(),buffers.back().size()) || buffers.back()!=patch->expected) {
            reason="patch expected bytes differ or cannot be read"; return false;
        }
    }
    // All allocations and preflight checks finish before changing page protections.
    // The caller must synchronize threads; this primitive cannot prove quiescence.
    std::size_t written{},protected_count{};
    const auto finish=[&](bool rollback) noexcept {
        bool good=true;
        if (rollback && written) {
            // A failed restoration may already have made some pages read-only.
            for (auto& page:pages) {
                DWORD old{};
                if (VirtualProtect(reinterpret_cast<void*>(page.address),page_size,Writable(page.original),&old)) page.changed=true;
                else good=false;
            }
            for (std::size_t i=0;i<written;++i) {
                SIZE_T copied{}; const auto* patch=ordered[i];
                if (!WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(patch->address),patch->expected.data(),patch->expected.size(),&copied) ||
                    copied!=patch->expected.size()) good=false;
            }
            if (!FlushInstructionCache(GetCurrentProcess(),nullptr,0)) good=false;
        }
        for (auto page=pages.rbegin();page!=pages.rend();++page) {
            if (!page->changed) continue;
            DWORD old{};
            if (VirtualProtect(reinterpret_cast<void*>(page->address),page_size,RestoreFlags(page->original),&old)) page->changed=false;
            else good=false;
        }
        return good;
    };
    const auto reject=[&](const char* message) {
        const bool restored=finish(true);
        reason=message;
        if (!restored) reason+="; rollback/protection recovery could not be confirmed";
        return false;
    };
    for (auto& page:pages) {
        DWORD old{};
        if (!VirtualProtect(reinterpret_cast<void*>(page.address),page_size,Writable(page.original),&old)) return reject("patch page protection failed");
        page.changed=true; ++protected_count;
        if (old!=page.original) { page.original=old; return reject("page protection changed during preflight"); }
        if (fail_after_protect>=0 && protected_count==static_cast<std::size_t>(fail_after_protect)) return reject("injected protect-stage failure");
    }
    for (std::size_t i=0;i<ordered.size();++i) {
        const auto* patch=ordered[i]; SIZE_T copied{};
        ++written; // Include the current span in rollback even if the API writes only part of it.
        if (!WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(patch->address),patch->replacement.data(),patch->replacement.size(),&copied) ||
            copied!=patch->replacement.size()) return reject("patch write failed or was partial");
        if (fail_after_write>=0 && written==static_cast<std::size_t>(fail_after_write)) return reject("injected write-stage failure");
    }
    for (std::size_t i=0;i<ordered.size();++i) {
        if (!ReadBytes(ordered[i]->address,buffers[i].data(),buffers[i].size()) || buffers[i]!=ordered[i]->replacement) return reject("written patch verification failed");
    }
    if (!FlushInstructionCache(GetCurrentProcess(),nullptr,0)) return reject("patch instruction-cache flush failed");
    if (!finish(false)) return reject("patch protection restoration failed");
    reason.clear(); return true;
}
}
bool ApplyPatchTransaction(const std::vector<MemoryPatch>& patches,std::string& reason) {
    return ApplyInternal(patches,reason,-1,-1);
}
bool RunPatchSelfChecks(std::string& reason) {
    SYSTEM_INFO info{}; GetSystemInfo(&info); const auto page_size=static_cast<std::size_t>(info.dwPageSize);
    auto* region=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,page_size*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!region) { reason="fixture memory allocation failed"; return false; }
    struct RegionOwner { void* pointer; ~RegionOwner() { VirtualFree(pointer,0,MEM_RELEASE); } } owner{region};
    const auto base=reinterpret_cast<std::uintptr_t>(region);
    const std::vector<MemoryPatch> patches{{base+page_size-2,{0x10,0x20,0x30,0x40,0x50,0x60},{0x90,0x91,0x92,0x93,0x94,0x95}},
        {base+page_size+32,{1,2,3,4},{5,6,7,8}}};
    for (const auto& patch:patches) std::memcpy(reinterpret_cast<void*>(patch.address),patch.expected.data(),patch.expected.size());
    region[page_size-3]=0xCB; region[page_size+4]=0xAD; region[page_size+31]=0x71; region[page_size+36]=0x81;
    DWORD ignored{};
    if (!VirtualProtect(region,page_size,PAGE_EXECUTE_READ,&ignored) ||
        !VirtualProtect(region+page_size,page_size,PAGE_READONLY,&ignored)) { reason="fixture protection setup failed"; return false; }
    const auto protections_ok=[&]() { return Protection(base)==PAGE_EXECUTE_READ && Protection(base+page_size)==PAGE_READONLY; };
    const auto bytes_match=[&](bool replaced) {
        for (const auto& patch:patches) {
            std::vector<std::uint8_t> actual(patch.expected.size());
            if (!ReadBytes(patch.address,actual.data(),actual.size()) || actual!=(replaced?patch.replacement:patch.expected)) return false;
        }
        return region[page_size-3]==0xCB && region[page_size+4]==0xAD && region[page_size+31]==0x71 && region[page_size+36]==0x81;
    };
    if (ApplyInternal(patches,reason,-1,1) || !bytes_match(false) || !protections_ok()) { reason="protect-stage rollback failed"; return false; }
    if (ApplyInternal(patches,reason,1,-1) || !bytes_match(false) || !protections_ok()) { reason="write-stage rollback failed"; return false; }
    auto bad=patches; bad[1].expected[0]=0xFF;
    if (ApplyPatchTransaction(bad,reason) || !bytes_match(false) || !protections_ok()) { reason="mismatched patch changed memory"; return false; }
    bad=patches; bad[1]=bad[0];
    if (ApplyPatchTransaction(bad,reason) || !bytes_match(false) || !protections_ok()) { reason="overlapping patch changed memory"; return false; }
    bad=patches; bad[0].replacement.pop_back();
    if (ApplyPatchTransaction(bad,reason) || !bytes_match(false) || !protections_ok()) { reason="length mismatch changed memory"; return false; }
    if (!ApplyPatchTransaction(patches,reason)) return false;
    if (!bytes_match(true) || !protections_ok()) { reason="commit crossed guards or lost per-page protection"; return false; }
    if (ApplyPatchTransaction(patches,reason) || !bytes_match(true) || !protections_ok()) { reason="stale expected bytes accepted on repeat"; return false; }
    bad={{UINTPTR_MAX-2,{1,2,3,4},{4,3,2,1}}};
    if (ApplyPatchTransaction(bad,reason)) { reason="overflowing patch address accepted"; return false; }
    reason.clear(); return true;
}
}

namespace channel_expand {
bool PreparedPatchTransaction::Prepare(const std::vector<MemoryPatch>& patches,std::string& reason) {
    if (ready_ || patches.empty() || patches.size()>sites_.size()) { reason="prepared transaction is nonempty, single-use and bounded to256 sites"; return false; }
    site_count_=page_count_=0; resume_safe_=false; dialect_=Dialect::Unknown;
    SYSTEM_INFO system{}; GetSystemInfo(&system); page_size_=system.dwPageSize;
    if (page_size_!=4096) { reason="unsupported prepared transaction page size"; return false; }
    for (const auto& patch:patches) {
        if (!patch.address || patch.expected.empty() || patch.expected.size()>32 || patch.expected.size()!=patch.replacement.size() ||
            patch.expected==patch.replacement || patch.address>UINTPTR_MAX-patch.expected.size()) {
            reason="prepared patch range, length or no-op invalid"; return false;
        }
        for (std::size_t i=0;i<site_count_;++i) if (patch.address<sites_[i].address+sites_[i].size &&
            sites_[i].address<patch.address+patch.expected.size()) { reason="prepared patches overlap"; return false; }
        auto& site=sites_[site_count_]; site={}; site.address=patch.address; site.size=patch.expected.size();
        std::memcpy(site.original.data(),patch.expected.data(),site.size);
        std::memcpy(site.replacement.data(),patch.replacement.data(),site.size);
        std::array<std::uint8_t,32> actual{};
        if (!ReadBytes(site.address,actual.data(),site.size) || std::memcmp(actual.data(),site.original.data(),site.size)) {
            reason="prepared patch expected bytes differ"; return false;
        }
        for (auto page=site.address&~std::uintptr_t{4095};page<site.address+site.size;) {
            bool found=false; for (std::size_t i=0;i<page_count_;++i) found|=pages_[i].address==page;
            if (!found) {
                MEMORY_BASIC_INFORMATION memory{};
                if (page_count_==pages_.size() || VirtualQuery(reinterpret_cast<void*>(page),&memory,sizeof(memory))!=sizeof(memory) ||
                    memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_NOACCESS|PAGE_GUARD)) || !(memory.Protect&0xFF)) {
                    reason="prepared patch page inaccessible or exceeds fixed capacity"; return false;
                }
                pages_[page_count_++]={page,memory.Protect,false};
            }
            if (page>UINTPTR_MAX-page_size_) { reason="prepared patch page overflow"; return false; }
            page+=page_size_;
        }
        ++site_count_;
    }
    // Preserve the caller's publication order, including pointer/context writes
    // last. Copy every operand: caller vector mutations cannot change this plan.
    ready_=true; dialect_=Dialect::Original; resume_safe_=true; failure_=nullptr; reason.clear(); return true;
}
bool PreparedPatchTransaction::Matches(bool replacement) const noexcept {
    std::array<std::uint8_t,32> actual{};
    for (std::size_t i=0;i<site_count_;++i) {
        const auto& site=sites_[i]; const auto& expected=replacement?site.replacement:site.original;
        if (!ReadBytes(site.address,actual.data(),site.size) || std::memcmp(actual.data(),expected.data(),site.size)) return false;
    }
    return true;
}
bool PreparedPatchTransaction::ProtectionsMatch() const noexcept {
    for (std::size_t i=0;i<page_count_;++i) if (pages_[i].writable || Protection(pages_[i].address)!=pages_[i].protection) return false;
    return true;
}
bool PreparedPatchTransaction::RestorePages(int inject) noexcept {
    bool good=true; std::size_t restored{};
    for (std::size_t i=page_count_;i>0;--i) if (pages_[i-1].writable) {
        auto& page=pages_[i-1]; DWORD old{};
        if (VirtualProtect(reinterpret_cast<void*>(page.address),page_size_,RestoreFlags(page.protection),&old)) page.writable=false;
        else good=false;
        ++restored;
        if (inject>=0 && restored==static_cast<std::size_t>(inject)) return false;
    }
    return good;
}
bool PreparedPatchTransaction::SiteWritable(std::size_t index) const noexcept {
    const auto& site=sites_[index];
    for (auto page=site.address&~std::uintptr_t{4095};page<site.address+site.size;page+=page_size_) {
        bool found=false;
        for (std::size_t i=0;i<page_count_;++i) if (pages_[i].address==page) found=pages_[i].writable;
        if (!found) return false;
    }
    return true;
}
bool PreparedPatchTransaction::Run(bool replacement,Fault fault) noexcept {
    failure_=nullptr;
    const auto before=replacement?Dialect::Original:Dialect::Replacement;
    const auto after=replacement?Dialect::Replacement:Dialect::Original;
    if (!ready_ || dialect_!=before) {
        resume_safe_=ready_ && dialect_!=Dialect::Unknown && Matches(dialect_==Dialect::Replacement) && ProtectionsMatch();
        if (ready_ && !resume_safe_) dialect_=Matches(false)?Dialect::Original:(Matches(true)?Dialect::Replacement:Dialect::Unknown);
        failure_="prepared transaction not in required starting dialect"; return false;
    }
    if (!Matches(!replacement) || !ProtectionsMatch()) {
        dialect_=Matches(false)?Dialect::Original:(Matches(true)?Dialect::Replacement:Dialect::Unknown);
        resume_safe_=false; failure_="prepared bytes/protections changed before synchronized write"; return false;
    }
    resume_safe_=false; std::size_t attempted{},protected_count{};
    const auto recover=[&](const char* message,bool evidence=true) noexcept {
        failure_=message; bool restored=evidence;
        if (attempted) {
            // A restoration-stage failure can leave an arbitrary RX/RW mixture.
            // Reopen all affected pages before undoing any full/partial span.
            for (std::size_t i=0;i<page_count_;++i) if (!pages_[i].writable) {
                DWORD old{}; auto& page=pages_[i];
                if (VirtualProtect(reinterpret_cast<void*>(page.address),page_size_,Writable(page.protection),&old)) page.writable=true;
                else restored=false;
            }
            while (attempted) {
                const auto i=--attempted; const auto& site=sites_[i]; const auto& bytes=replacement?site.original:site.replacement;
                SIZE_T copied{};
                if (!SiteWritable(i) || !WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(site.address),bytes.data(),site.size,&copied) || copied!=site.size) restored=false;
            }
        }
        const bool original=Matches(false),changed=Matches(true);
        dialect_=original?Dialect::Original:(changed?Dialect::Replacement:Dialect::Unknown);
        const bool cache=FlushInstructionCache(GetCurrentProcess(),nullptr,0)!=FALSE;
        const bool protections=RestorePages(-1) && ProtectionsMatch();
        resume_safe_=restored && dialect_==before && cache && protections;
        return false;
    };
    for (std::size_t i=0;i<page_count_;++i) {
        auto& page=pages_[i]; DWORD old{};
        if (!VirtualProtect(reinterpret_cast<void*>(page.address),page_size_,Writable(page.protection),&old)) return recover("prepared page protection failed");
        page.writable=true; ++protected_count;
        if (old!=page.protection) return recover("prepared page protection raced",false);
        if (fault.after_protect>=0 && protected_count==static_cast<std::size_t>(fault.after_protect)) return recover("injected prepared protect failure");
    }
    for (std::size_t i=0;i<site_count_;++i) {
        const auto& site=sites_[i]; const auto& bytes=replacement?site.replacement:site.original; SIZE_T copied{};
        ++attempted; // Roll back the current span even after a partial API write.
        if (!SiteWritable(i) || !WriteProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(site.address),bytes.data(),site.size,&copied) || copied!=site.size)
            return recover("prepared write failed or partial");
        if (fault.after_write>=0 && attempted==static_cast<std::size_t>(fault.after_write)) return recover("injected prepared write failure");
    }
    if (!Matches(replacement)) return recover("prepared full-span verification failed");
    if (fault.before_flush) return recover("injected prepared pre-flush failure");
    if (!FlushInstructionCache(GetCurrentProcess(),nullptr,0)) return recover("prepared instruction cache flush failed");
    if (!RestorePages(fault.after_restore) || !ProtectionsMatch()) return recover("prepared protection restoration failed");
    dialect_=after; resume_safe_=true; return true;
}
bool PreparedPatchTransaction::ApplyWhileQuiescent(Fault fault) noexcept { return Run(true,fault); }
bool PreparedPatchTransaction::RestoreWhileQuiescent(Fault fault) noexcept { return Run(false,fault); }
bool RunPreparedPatchSelfChecks(std::string& reason) {
    constexpr std::size_t page=4096,total=4*page;
    auto* region=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,total,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!region) { reason="prepared fixture allocation failed"; return false; }
    struct Owner { void* pointer; ~Owner(){VirtualFree(pointer,0,MEM_RELEASE);} } owner{region};
    std::memset(region,0xCB,total); const auto base=reinterpret_cast<std::uintptr_t>(region);
    std::vector<MemoryPatch> patches;
    //112 distinct spans match the current95+14+3 plan size. Include32-byte
    //data, 1-byte/unaligned instruction fields and a cross-page instruction.
    for (std::size_t i=0;i<112;++i) {
        const auto offset=i==111?page-3:64+(i/28)*page+(i%28)*48;
        const auto length=i==111?std::size_t{15}:1+i%32;
        MemoryPatch patch; patch.address=base+offset; patch.expected.assign(length,static_cast<std::uint8_t>(i));
        patch.replacement.assign(length,static_cast<std::uint8_t>(i+128));
        std::memcpy(region+offset,patch.expected.data(),length); patches.push_back(std::move(patch));
    }
    const std::vector<std::uint8_t> original(region,region+total); auto expected=original;
    for (const auto& patch:patches) std::memcpy(expected.data()+patch.address-base,patch.replacement.data(),patch.replacement.size());
    constexpr std::array<DWORD,4> protections{PAGE_EXECUTE_READ,PAGE_READONLY,PAGE_READWRITE,PAGE_EXECUTE_READ}; DWORD old{};
    for (std::size_t i=0;i<4;++i) if (!VirtualProtect(region+i*page,page,protections[i],&old)) { reason="prepared fixture protections failed"; return false; }
    const auto matches=[&](bool changed) { return !std::memcmp(region,(changed?expected:original).data(),total); };
    const auto protected_ok=[&](){for (std::size_t i=0;i<4;++i) if (Protection(base+i*page)!=protections[i]) return false; return true;};
    auto transaction=std::make_unique<PreparedPatchTransaction>();
    if (!transaction->Prepare(patches,reason) || transaction->site_count()!=112) return false;
    // Already prepared input is copied; subsequent caller edits cannot affect it.
    patches[0].replacement[0]^=1;
    for (int i=1;i<=112;++i) {
        if (transaction->ApplyWhileQuiescent({i,-1,-1,false}) || !transaction->resume_safe() ||
            transaction->dialect()!=PreparedPatchTransaction::Dialect::Original || !matches(false) || !protected_ok()) {
            reason="prepared112-stage write rollback failed"; return false;
        }
    }
    for (int i=1;i<=4;++i) for (const bool restore:{false,true}) {
        if (transaction->ApplyWhileQuiescent({-1,restore?-1:i,restore?i:-1,false}) || !transaction->resume_safe() ||
            transaction->dialect()!=PreparedPatchTransaction::Dialect::Original || !matches(false) || !protected_ok()) {
            reason="prepared protect/restoration stage recovery failed"; return false;
        }
    }
    if (transaction->ApplyWhileQuiescent({-1,-1,-1,true}) || !transaction->resume_safe() || !matches(false) || !protected_ok()) {
        reason="prepared cache-stage rollback failed"; return false;
    }
    if (!transaction->ApplyWhileQuiescent({}) || transaction->dialect()!=PreparedPatchTransaction::Dialect::Replacement ||
        !transaction->resume_safe() || !matches(true) || !protected_ok()) { reason="prepared commit failed"; return false; }
    if (transaction->ApplyWhileQuiescent({}) || !matches(true) || !protected_ok()) { reason="prepared duplicate commit accepted"; return false; }
    for (int i=1;i<=112;++i) {
        if (transaction->RestoreWhileQuiescent({i,-1,-1,false}) || !transaction->resume_safe() ||
            transaction->dialect()!=PreparedPatchTransaction::Dialect::Replacement || !matches(true) || !protected_ok()) {
            reason="prepared reverse transaction rollback failed"; return false;
        }
    }
    if (!transaction->RestoreWhileQuiescent({}) || !transaction->resume_safe() || !matches(false) || !protected_ok()) {
        reason="prepared full restoration failed"; return false;
    }
    for (int bad=0;bad<7;++bad) {
        auto invalid=patches;
        if (bad==0) invalid[0].address=UINTPTR_MAX-1;
        if (bad==1) invalid[1]=invalid[0];
        if (bad==2) invalid[0].replacement.pop_back();
        if (bad==3) invalid[0].expected[0]^=1;
        if (bad==4) invalid.resize(257,invalid[0]);
        if (bad==5) invalid[0].replacement=invalid[0].expected;
        if (bad==6) { invalid[0].expected.resize(33); invalid[0].replacement.resize(33); }
        auto rejected=std::make_unique<PreparedPatchTransaction>();
        if (rejected->Prepare(invalid,reason) || !matches(false) || !protected_ok()) { reason="invalid prepared range/count accepted"; return false; }
    }
    auto stale_protection=std::make_unique<PreparedPatchTransaction>();
    if (!stale_protection->Prepare(patches,reason) || !VirtualProtect(region,page,PAGE_EXECUTE_READWRITE,&old)) return false;
    if (stale_protection->ApplyWhileQuiescent({}) || stale_protection->resume_safe() || !matches(false) ||
        Protection(base)!=PAGE_EXECUTE_READWRITE) { reason="foreign prepared protection was changed or declared safe"; return false; }
    if (!VirtualProtect(region,page,protections[0],&old)) return false;
    // Foreign bytes after preparation must refuse without making the caller
    //believe the original/context pairing is safe to resume.
    auto stale=std::make_unique<PreparedPatchTransaction>();
    if (!stale->Prepare(patches,reason) || !VirtualProtect(region,page,PAGE_READWRITE,&old)) return false;
    region[64]^=1;
    if (!VirtualProtect(region,page,protections[0],&old)) return false;
    if (stale->ApplyWhileQuiescent({}) || stale->resume_safe() || stale->dialect()!=PreparedPatchTransaction::Dialect::Unknown ||
        region[64]!=(original[64]^1) || !protected_ok()) { reason="stale prepared byte state was declared safe"; return false; }
    reason.clear(); return true;
}
}

namespace channel_expand {
bool RunEngineRelocationTransaction(const std::filesystem::path& path,std::string& reason) {
    const auto inspected=InspectEngine(path);
    if (!inspected.parsed || !inspected.manifest.supported || inspected.manifest.sha256!=kExpectedSha) {
        reason="relocation transaction requires exact supported engine Build"; return false;
    }
    const auto& image=inspected.image;
    auto* region=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,image.image_size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!region) { reason="private engine image fixture allocation failed"; return false; }
    struct Owner { void* ptr; ~Owner(){VirtualFree(ptr,0,MEM_RELEASE);} } owner{region};
    for (const auto& section:image.sections) {
        if (section.offset>image.bytes.size() || section.raw_size>image.bytes.size()-section.offset ||
            section.rva>image.image_size || section.raw_size>image.image_size-section.rva) {
            reason="private engine image section extent invalid"; return false;
        }
        if (section.raw_size) std::memcpy(region+section.rva,image.bytes.data()+section.offset,section.raw_size);
    }
    // This image is neither LoadLibrary'd nor executed; no DllMain, Lua or
    // Source API runs. Only original instruction spans are copied and patched.
    const auto base=reinterpret_cast<std::uintptr_t>(region);
    NearChannelStorage storage;
    if (!storage.Prepare(base,image.image_size,reason)) return false;
    StorageRedirectPlan plan;
    if (!BuildStorageRedirectPlan(inspected.manifest,image,base,reinterpret_cast<std::uintptr_t>(storage.channels()),
        reinterpret_cast<std::uintptr_t>(storage.active()),plan,reason)) return false;
    std::vector<MemoryPatch> patches=plan.patches;
    patches.insert(patches.end(),plan.legacy_loads.begin(),plan.legacy_loads.end());
    patches.insert(patches.end(),plan.capacity_patches.begin(),plan.capacity_patches.end());
    if (patches.size()!=112 || plan.pending.size()!=108) { reason="real instruction transaction inventory count differs"; return false; }
    const std::vector<std::uint8_t> original(region,region+image.image_size); auto expected=original;
    for (const auto& patch:patches) std::memcpy(expected.data()+patch.address-base,patch.replacement.data(),patch.replacement.size());
    DWORD old{};
    for (const auto& section:image.sections) if (section.flags&IMAGE_SCN_MEM_EXECUTE) {
        const auto size=std::max(section.virtual_size,section.raw_size);
        if (!VirtualProtect(region+section.rva,size,PAGE_EXECUTE_READ,&old)) { reason="private engine text RX protection failed"; return false; }
    }
    auto transaction=std::make_unique<PreparedPatchTransaction>();
    if (!transaction->Prepare(patches,reason)) return false;
    const auto matches=[&](bool replaced){return !std::memcmp(region,(replaced?expected:original).data(),image.image_size);};
    const auto protected_ok=[&](){
        for (const auto& patch:patches) for (auto page=patch.address&~std::uintptr_t{4095};page<patch.address+patch.expected.size();page+=4096)
            if (Protection(page)!=PAGE_EXECUTE_READ) return false;
        return true;
    };
    for (const int i:{1,56,112}) {
        if (transaction->ApplyWhileQuiescent({i,-1,-1,false}) || !transaction->resume_safe() ||
            transaction->dialect()!=PreparedPatchTransaction::Dialect::Original || !matches(false) || !protected_ok() || !storage.GuardsIntact()) {
            reason="actual112 instruction spans failed rollback/readback/protection"; return false;
        }
    }
    if (transaction->ApplyWhileQuiescent({-1,-1,1,false}) || !transaction->resume_safe() || !matches(false) || !protected_ok()) {
        reason="actual relocation restore-stage rollback failed"; return false;
    }
    if (!transaction->ApplyWhileQuiescent({}) || !transaction->resume_safe() || !matches(true) || !protected_ok() || !storage.GuardsIntact()) {
        reason="actual relocation commit failed"; return false;
    }
    // Normalize the complete registered spans against the same immutable plan
    // and prove unrelated file bytes are unchanged, independently of Write.
    std::vector<std::uint8_t> normalized(region,region+image.image_size);
    if (!NormalizeRegisteredPatchBytes(patches,base,normalized) || normalized!=original) {
        reason="real relocation registry normalization differs from original image"; return false;
    }
    if (!transaction->RestoreWhileQuiescent({}) || !transaction->resume_safe() || !matches(false) || !protected_ok() || !storage.GuardsIntact()) {
        reason="actual relocation original restoration failed"; return false;
    }
    // Test the real128 relocation boundary independently of capacity/load
    // changes:95 code spans +3 actual NativeGuidContext pointer fields.
    const auto old_view=OriginalNativeStorageView(base);
    const NativeStorageView new_view{storage.channels(),&storage.active()->count,storage.active()->indices.data(),128};
    auto context=std::make_unique<NativeGuidContext>();
    context->channels=old_view.channels; context->active_count=old_view.active_count;
    context->active_indices=old_view.active_indices; context->capacity=128;
    std::vector<MemoryPatch> context_patches;
    if (!BuildStorageContextPatches(old_view,new_view,*context,context_patches,reason)) return false;
    auto relocated_patches=plan.patches;
    relocated_patches.insert(relocated_patches.end(),context_patches.begin(),context_patches.end());
    auto relocation=std::make_unique<PreparedPatchTransaction>();
    if (!relocation->Prepare(relocated_patches,reason) || relocation->site_count()!=98) return false;
    auto relocated_image=original;
    for (const auto& patch:plan.patches) std::memcpy(relocated_image.data()+patch.address-base,patch.replacement.data(),patch.replacement.size());
    std::atomic<const NativeStorageView*> published_view{&old_view};
    const auto context_matches=[&](const NativeStorageView& view) {
        return context->channels==view.channels && context->active_count==view.active_count &&
            context->active_indices==view.active_indices && context->capacity==view.capacity;
    };
    for (int stage=1;stage<=98;++stage) {
        if (relocation->ApplyWhileQuiescent({stage,-1,-1,false}) || !relocation->resume_safe() ||
            relocation->dialect()!=PreparedPatchTransaction::Dialect::Original || !matches(false) ||
            !context_matches(old_view) || published_view.load()!=&old_view || !protected_ok()) {
            reason="real98-span code/context rollback failed"; return false;
        }
    }
    if (!relocation->ApplyWhileQuiescent({}) || !relocation->resume_safe() || !context_matches(new_view) ||
        std::memcmp(region,relocated_image.data(),image.image_size) || !protected_ok() || !storage.GuardsIntact()) {
        reason="real code/context coupled commit failed"; return false;
    }
    published_view.store(&new_view,std::memory_order_release);
    if (!context_matches(*published_view.load(std::memory_order_acquire))) { reason="published view/context mismatch"; return false; }
    std::vector<std::uint8_t> relocated_readback(region,region+image.image_size);
    if (!NormalizeRegisteredPatchBytes(plan.patches,base,relocated_readback) || relocated_readback!=original) {
        reason="relocation-only normalization registry differs"; return false;
    }
    auto invalid_view=new_view; invalid_view.capacity=512;
    if (BuildStorageContextPatches(old_view,invalid_view,*context,context_patches,reason)) { reason="unverified512 descriptor accepted"; return false; }
    if (!relocation->RestoreWhileQuiescent({}) || !relocation->resume_safe() || !matches(false) || !context_matches(old_view)) {
        reason="real code/context original restoration failed"; return false;
    }
    published_view.store(&old_view,std::memory_order_release);
    // Actual three known code limits and the consumer's uint32 capacity commit
    // together, after the same95+3 relocated pointer state has been established.
    if (!relocation->ApplyWhileQuiescent({})) { reason="capacity fixture relocation prerequisite failed"; return false; }
    published_view.store(&new_view,std::memory_order_release);
    std::vector<MemoryPatch> boundaries;
    if (!BuildCapacityBoundaryPlan(inspected.manifest,image,base,boundaries,reason)) return false;
    auto capacity_writes=boundaries;
    MemoryPatch capacity_field; capacity_field.address=reinterpret_cast<std::uintptr_t>(&context->capacity);
    capacity_field.expected.resize(4); capacity_field.replacement.resize(4);
    const std::uint32_t cap128=128,cap512=512;
    std::memcpy(capacity_field.expected.data(),&cap128,4); std::memcpy(capacity_field.replacement.data(),&cap512,4);
    capacity_writes.push_back(std::move(capacity_field));
    auto capacity_tx=std::make_unique<PreparedPatchTransaction>();
    if (!capacity_tx->Prepare(capacity_writes,reason)) return false;
    const auto before_capacity=relocated_image; auto after_capacity=before_capacity;
    for (const auto& patch:boundaries) std::memcpy(after_capacity.data()+patch.address-base,patch.replacement.data(),patch.replacement.size());
    for (int stage=1;stage<=4;++stage) {
        if (capacity_tx->ApplyWhileQuiescent({stage,-1,-1,false}) || !capacity_tx->resume_safe() || context->capacity!=128 ||
            published_view.load()!=&new_view || std::memcmp(region,before_capacity.data(),image.image_size) || !protected_ok()) {
            reason="capacity four-stage code/context recovery failed"; return false;
        }
    }
    auto expanded_view=new_view; expanded_view.capacity=512;
    if (!ValidateNativeStorageView(expanded_view,reason) || !capacity_tx->ApplyWhileQuiescent({}) || context->capacity!=512 ||
        std::memcmp(region,after_capacity.data(),image.image_size) || !protected_ok() || !storage.GuardsIntact()) {
        reason="capacity code/context commit failed"; return false;
    }
    published_view.store(&expanded_view,std::memory_order_release);
    if (!context_matches(*published_view.load(std::memory_order_acquire))) { reason="expanded published view/context disagree"; return false; }
    auto registry=plan.patches; registry.insert(registry.end(),boundaries.begin(),boundaries.end());
    std::vector<std::uint8_t> expanded_readback(region,region+image.image_size);
    if (!NormalizeRegisteredPatchBytes(registry,base,expanded_readback) || expanded_readback!=original) {
        reason="combined relocation/capacity registry normalization failed"; return false;
    }
    if (!capacity_tx->RestoreWhileQuiescent({}) || context->capacity!=128 || std::memcmp(region,before_capacity.data(),image.image_size)) {
        reason="capacity full original restoration failed"; return false;
    }
    published_view.store(&new_view,std::memory_order_release);
    if (!relocation->RestoreWhileQuiescent({}) || !matches(false) || !context_matches(old_view)) {
        reason="post-capacity relocation restoration failed"; return false;
    }
    published_view.store(&old_view,std::memory_order_release);
    reason.clear(); return true;
}
}

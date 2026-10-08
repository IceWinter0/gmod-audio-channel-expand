#include "native_protocol.hpp"
#include <cstring>
#include <algorithm>
namespace channel_expand {
bool ValidateNativeRequest(const NativeRequestV1& r,std::string& reason) {
    if (r.magic!=kNativeMagic || r.abi!=kNativeAbi || r.size!=sizeof(r)) { reason="native protocol magic/ABI/size mismatch"; return false; }
    if (!r.request_id || r.reserved || !std::all_of(std::begin(r.reserved_tail),std::end(r.reserved_tail),[](std::uint8_t x){return !x;})) { reason="native request id/reserved fields invalid"; return false; }
    if (r.action<1 || r.action>3 || (r.flags&~(kNativeAck|kNativeClearOnce))) { reason="unknown native action/options"; return false; }
    if (r.action==static_cast<std::uint32_t>(NativeAction::Start)) {
        if (!(r.flags&kNativeAck)) { reason="native start requires fail-stop acknowledgment"; return false; }
    } else if (r.flags) { reason="query/readiness must not request writes"; return false; }
    reason.clear(); return true;
}
void SetNativeReason(NativeRequestV1& r,const std::string& value) noexcept {
    std::memset(r.reason,0,sizeof(r.reason));
    std::size_t keep=0;
    for (std::size_t at=0;at<value.size();) {
        const auto first=static_cast<unsigned char>(value[at]);
        std::size_t length=0;
        if (first<0x80) length=1;
        else if (first>=0xC2 && first<=0xDF) length=2;
        else if (first>=0xE0 && first<=0xEF) length=3;
        else if (first>=0xF0 && first<=0xF4) length=4;
        bool valid=length && length<=value.size()-at && first!=0;
        for (std::size_t j=1;valid && j<length;++j) valid=(static_cast<unsigned char>(value[at+j])&0xC0)==0x80;
        if (valid && length>=3) {
            const auto next=static_cast<unsigned char>(value[at+1]);
            if ((first==0xE0 && next<0xA0) || (first==0xED && next>=0xA0) ||
                (first==0xF0 && next<0x90) || (first==0xF4 && next>=0x90)) valid=false;
        }
        if (!valid) { constexpr char bad[]="invalid UTF-8 diagnostic"; std::memcpy(r.reason,bad,sizeof(bad)); return; }
        at+=length;
        if (at<sizeof(r.reason)) keep=at;
    }
    if (keep) std::memcpy(r.reason,value.data(),keep);
}
bool RunNativeProtocolSelfChecks(std::string& reason) {
    NativeRequestV1 good; good.action=static_cast<std::uint32_t>(NativeAction::Start); good.flags=kNativeAck|kNativeClearOnce; good.request_id=1;
    if (!ValidateNativeRequest(good,reason)) return false;
    const auto reject=[&](const NativeRequestV1& bad) { std::string why; return !ValidateNativeRequest(bad,why) && !why.empty(); };
    auto bad=good; bad.magic=0; if (!reject(bad)) { reason="bad magic accepted"; return false; }
    bad=good; bad.abi=2; if (!reject(bad)) { reason="bad ABI accepted"; return false; }
    bad=good; bad.size=1023; if (!reject(bad)) { reason="bad size accepted"; return false; }
    bad=good; bad.action=4; if (!reject(bad)) { reason="bad action accepted"; return false; }
    bad=good; bad.flags=4; if (!reject(bad)) { reason="bad flag accepted"; return false; }
    bad=good; bad.reserved=1; if (!reject(bad)) { reason="reserved field accepted"; return false; }
    bad=good; bad.reserved_tail[375]=1; if (!reject(bad)) { reason="reserved tail accepted"; return false; }
    bad=good; bad.request_id=0; if (!reject(bad)) { reason="zero request id accepted"; return false; }
    bad=good; bad.action=1; if (!reject(bad)) { reason="flags on readiness accepted"; return false; }
    bad.flags=0; if (!ValidateNativeRequest(bad,reason)) return false;
    bad.action=3; if (!ValidateNativeRequest(bad,reason)) return false;
    bad=good; bad.flags=0; if (!reject(bad)) { reason="unacknowledged start accepted"; return false; }
    good.frames=0xFEDCBA9876543210ull; if (good.frames!=0xFEDCBA9876543210ull) { reason="64-bit count truncated"; return false; }
    SetNativeReason(good,std::string(510,'a')+"\xE4\xB8\xAD");
    if (std::strlen(good.reason)!=510) { reason="UTF8 truncated inside codepoint"; return false; }
    SetNativeReason(good,"\xC0\xAF"); if (std::string(good.reason)!="invalid UTF-8 diagnostic") { reason="malformed UTF8 accepted"; return false; }
    reason.clear(); return true;
}
}

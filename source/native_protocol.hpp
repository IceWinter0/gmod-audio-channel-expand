#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
namespace channel_expand {
constexpr std::uint32_t kNativeMagic=0x43453531, kNativeAbi=1;
enum class NativeAction : std::uint32_t { Readiness=1, Start=2, Query=3 };
enum class NativeState : std::uint32_t { Idle=0, Waiting=1, Active=2, Rejected=3, RestartRequired=4, Failed=5 };
enum class NativeStage : std::uint32_t { None=0, Engine=1, Audio=2, Validating=3, Empty=4, Frame=5, Snapshot=6, Storage=7, Capacity=8, Complete=9 };
constexpr std::uint32_t kNativeAck=1, kNativeClearOnce=2;
constexpr std::uint32_t kDiagCodeMatches=1, kDiagCountsValid=2, kDiagStorageGuards=4, kDiagFrameActive=8, kDiagSnapshotActive=16, kDiagStorageActive=32, kDiagCapacityActive=64;
struct alignas(8) NativeRequestV1 {
    std::uint32_t magic{kNativeMagic}, abi{kNativeAbi}, size{1024}, action{};
    std::uint32_t flags{}, reserved{};
    std::uint64_t request_id{};
    std::uint32_t state{}, stage{}, win32_error{}, capacity{};
    std::int32_t active{-1}, dynamic{-1}, statics{-1}, total{-1};
    std::uint64_t errors{}, fallback{}, frames{}, preprocessed{}, backend{}, paint{}, mixed{}, freed{};
    std::uint32_t storage_redirects{}, diagnostic_flags{};
    char reason[512]{};
    std::uint8_t reserved_tail[376]{};
};
static_assert(sizeof(NativeRequestV1)==1024 && alignof(NativeRequestV1)==8);
static_assert(offsetof(NativeRequestV1,request_id)==24 && offsetof(NativeRequestV1,state)==32);
static_assert(offsetof(NativeRequestV1,errors)==64 && offsetof(NativeRequestV1,reason)==136);
bool ValidateNativeRequest(const NativeRequestV1&,std::string&);
void SetNativeReason(NativeRequestV1&,const std::string&) noexcept;
bool RunNativeProtocolSelfChecks(std::string&);
NativeRequestV1 QueryNativeSession(bool readiness);
NativeRequestV1 StartNativeSession(std::uint32_t flags,std::uintptr_t return_slot);
}

#include "SceTypes.hpp"
#include <array>
#include <cstddef>
#include <cstdlib>
#include <future>
#include <stdexcept>

extern "C" {
int APS5_VABI scePthreadCreate(Pthread* thread, const PthreadAttr* attr, PthreadEntry entry, void* arg, const char* name);
int APS5_VABI scePthreadJoin(Pthread thread, void** retval);
int APS5_VABI scePthreadSetprio(Pthread thread, int prio);
int APS5_VABI scePthreadSetaffinity(Pthread thread, KernelCpumask mask);
int APS5_VABI scePthreadAttrInit(PthreadAttr* attr);
int APS5_VABI scePthreadAttrDestroy(PthreadAttr* attr);
int APS5_VABI scePthreadAttrGet(Pthread thread, PthreadAttr* attr);
int APS5_VABI scePthreadAttrSetinheritsched(PthreadAttr* attr, int inheritSched);
int APS5_VABI scePthreadAttrSetschedparam(PthreadAttr* attr, const KernelSchedParam* param);
int APS5_VABI scePthreadAttrSetaffinity(PthreadAttr* attr, KernelCpumask mask);
int APS5_VABI scePthreadAttrSetstacksize(PthreadAttr* attr, std::size_t stackSize);
int APS5_VABI scePthreadAttrGetschedparam(const PthreadAttr* attr, KernelSchedParam* param);
int APS5_VABI scePthreadAttrGetaffinity(const PthreadAttr* attr, KernelCpumask* mask);
int APS5_VABI scePthreadAttrGetstacksize(const PthreadAttr* attr, std::size_t* stackSize);
int APS5_VABI scePthreadAttrGetdetachstate(const PthreadAttr* attr, int* state);
int APS5_VABI scePthreadAttrGetsolosched(const PthreadAttr* attr, int* solosched);
int APS5_VABI pthread_attr_setstacksize_nid_postfix(PthreadAttr* attr, std::size_t stackSize);
int APS5_VABI pthread_attr_setsolosched_np_nid_postfix(PthreadAttr* attr, int solosched);
int APS5_VABI pthread_attr_init_nid_postfix(PthreadAttr* attr);
int APS5_VABI pthread_attr_destroy_nid_postfix(PthreadAttr* attr);
int APS5_VABI pthread_attr_get_np_nid_postfix(Pthread thread, PthreadAttr* attr);
int APS5_VABI pthread_attr_getinheritsched_nid_postfix(const PthreadAttr* attr, int* inheritSched);
int APS5_VABI pthread_attr_setinheritsched_nid_postfix(PthreadAttr* attr, int inheritSched);
int APS5_VABI pthread_attr_getscope_nid_postfix(const PthreadAttr* attr, int* scope);
int APS5_VABI pthread_attr_setscope_nid_postfix(PthreadAttr* attr, int scope);
int APS5_VABI pthread_create_nid_postfix(Pthread* thread, const PthreadAttr* attr, PthreadEntry entry, void* arg);
int APS5_VABI pthread_join_nid_postfix(Pthread thread, void** retval);
}

static constexpr int SCE_OK = 0;
static constexpr int SCE_KERNEL_ERROR_EINVAL = static_cast<int>(0x80020016);
static constexpr int EXPLICIT_SCHED = 0;
static constexpr int DETACH_JOINABLE = 0;
static constexpr int CREATION_PRIORITY = 256;
static constexpr int UPDATED_PRIORITY = 767;
static constexpr KernelCpumask CREATION_AFFINITY = 0x3;
static constexpr KernelCpumask UPDATED_AFFINITY = 0x1000;
static constexpr std::size_t STACK_SIZE = 2u << 20;
static constexpr std::size_t MIN_STACK_SIZE = 16384;
static constexpr int GUEST_EINVAL = 22;
static constexpr int GUEST_ENOTSUP = 45;
static constexpr int INHERIT_SCHED = 4;
static constexpr int SCOPE_PROCESS = 0;
static constexpr int SCOPE_SYSTEM = 2;

static void Require(bool value) { if (!value) std::abort(); }

struct ReportedAttributes {
    int priority = 0;
    KernelCpumask affinity = 0;
    std::size_t stackSize = 0;
    int detachState = -1;
};

extern "C" {
int APS5_VABI pthread_attr_setstack_nid_postfix(PthreadAttr* attr, void* addr, std::size_t size);
int APS5_VABI pthread_attr_getstack_nid_postfix(const PthreadAttr* attr, void** addr, std::size_t* size);
}

static ReportedAttributes Query(Pthread thread) {
    PthreadAttr attr = nullptr;
    Require(scePthreadAttrInit(&attr) == SCE_OK);
    Require(scePthreadAttrGet(thread, &attr) == SCE_OK);
    ReportedAttributes reported;
    KernelSchedParam param{};
    Require(scePthreadAttrGetschedparam(&attr, &param) == SCE_OK);
    reported.priority = param.sched_priority;
    Require(scePthreadAttrGetaffinity(&attr, &reported.affinity) == SCE_OK);
    Require(scePthreadAttrGetstacksize(&attr, &reported.stackSize) == SCE_OK);
    Require(scePthreadAttrGetdetachstate(&attr, &reported.detachState) == SCE_OK);
    Require(scePthreadAttrDestroy(&attr) == SCE_OK);
    return reported;
}

static void CheckStackSizeLimit() {
    PthreadAttr attr = nullptr;
    Require(scePthreadAttrInit(&attr) == SCE_OK);
    std::size_t stackSize = 0;
    Require(scePthreadAttrSetstacksize(&attr, MIN_STACK_SIZE) == SCE_OK);
    Require(scePthreadAttrGetstacksize(&attr, &stackSize) == SCE_OK && stackSize == MIN_STACK_SIZE);
    Require(scePthreadAttrSetstacksize(&attr, MIN_STACK_SIZE - 1) == SCE_KERNEL_ERROR_EINVAL);
    Require(scePthreadAttrSetstacksize(&attr, 0) == SCE_KERNEL_ERROR_EINVAL);
    Require(pthread_attr_setstacksize_nid_postfix(&attr, MIN_STACK_SIZE - 1) == GUEST_EINVAL);
    Require(scePthreadAttrGetstacksize(&attr, &stackSize) == SCE_OK && stackSize == MIN_STACK_SIZE);
    Require(scePthreadAttrDestroy(&attr) == SCE_OK);
}

static void CheckSoloSched() {
    PthreadAttr attr = nullptr;
    Require(pthread_attr_setsolosched_np_nid_postfix(nullptr, 1) == GUEST_EINVAL);
    Require(pthread_attr_setsolosched_np_nid_postfix(&attr, 1) == GUEST_EINVAL);
    Require(scePthreadAttrInit(&attr) == SCE_OK);
    int soloSched = -1;
    Require(scePthreadAttrGetsolosched(&attr, &soloSched) == SCE_OK && soloSched == 0);
    Require(pthread_attr_setsolosched_np_nid_postfix(&attr, 1) == 0);
    Require(scePthreadAttrGetsolosched(&attr, &soloSched) == SCE_OK && soloSched == 1);
    Require(pthread_attr_setsolosched_np_nid_postfix(&attr, 0) == 0);
    Require(scePthreadAttrGetsolosched(&attr, &soloSched) == SCE_OK && soloSched == 0);
    Require(scePthreadAttrDestroy(&attr) == SCE_OK);
    Require(pthread_attr_setsolosched_np_nid_postfix(&attr, 1) == GUEST_EINVAL);
}

static void* APS5_VABI Worker(void* arg) {
    static_cast<std::future<void>*>(arg)->get();
    return nullptr;
}

static int Inheritsched(const PthreadAttr& attr) {
    int value = -1;
    Require(pthread_attr_getinheritsched_nid_postfix(&attr, &value) == 0);
    return value;
}

static int Scope(const PthreadAttr& attr) {
    int value = -1;
    Require(pthread_attr_getscope_nid_postfix(&attr, &value) == 0);
    return value;
}

static void CheckSchedulingAttributes() {
    PthreadAttr attr = nullptr;
    Require(pthread_attr_init_nid_postfix(&attr) == 0);
    Require(Inheritsched(attr) == INHERIT_SCHED);
    Require(Scope(attr) == SCOPE_SYSTEM);

    Require(pthread_attr_setinheritsched_nid_postfix(&attr, EXPLICIT_SCHED) == 0);
    Require(Inheritsched(attr) == EXPLICIT_SCHED);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, 1) == GUEST_ENOTSUP);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, -1) == GUEST_ENOTSUP);
    Require(Inheritsched(attr) == EXPLICIT_SCHED);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, INHERIT_SCHED) == 0);
    Require(Inheritsched(attr) == INHERIT_SCHED);

    Require(pthread_attr_setscope_nid_postfix(&attr, SCOPE_PROCESS) == 0);
    Require(Scope(attr) == SCOPE_PROCESS);
    Require(pthread_attr_setscope_nid_postfix(&attr, 1) == GUEST_EINVAL);
    Require(pthread_attr_setscope_nid_postfix(&attr, 3) == GUEST_EINVAL);
    Require(Scope(attr) == SCOPE_PROCESS);
    Require(pthread_attr_setscope_nid_postfix(&attr, SCOPE_SYSTEM) == 0);
    Require(Scope(attr) == SCOPE_SYSTEM);

    int value = -1;
    Require(pthread_attr_getscope_nid_postfix(&attr, nullptr) == GUEST_EINVAL);
    bool threw = false;
    try { pthread_attr_getinheritsched_nid_postfix(&attr, nullptr); } catch (const std::runtime_error&) { threw = true; }
    Require(threw);
    Require(pthread_attr_destroy_nid_postfix(&attr) == 0);

    Require(pthread_attr_getinheritsched_nid_postfix(&attr, &value) == GUEST_EINVAL);
    Require(pthread_attr_getscope_nid_postfix(&attr, &value) == GUEST_EINVAL);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, INHERIT_SCHED) == GUEST_EINVAL);
    Require(pthread_attr_setscope_nid_postfix(&attr, SCOPE_SYSTEM) == GUEST_EINVAL);
    Require(pthread_attr_getinheritsched_nid_postfix(nullptr, &value) == GUEST_EINVAL);
    Require(pthread_attr_getscope_nid_postfix(nullptr, &value) == GUEST_EINVAL);
    Require(pthread_attr_setinheritsched_nid_postfix(nullptr, INHERIT_SCHED) == GUEST_EINVAL);
    Require(pthread_attr_setscope_nid_postfix(nullptr, SCOPE_SYSTEM) == GUEST_EINVAL);
    Require(value == -1);
}

static int ThreadScope(Pthread thread, int stale) {
    PthreadAttr attr = nullptr;
    Require(pthread_attr_init_nid_postfix(&attr) == 0);
    Require(pthread_attr_setscope_nid_postfix(&attr, stale) == 0);
    Require(pthread_attr_get_np_nid_postfix(thread, &attr) == 0);
    const int posix = Scope(attr);
    Require(pthread_attr_setscope_nid_postfix(&attr, stale) == 0);
    Require(scePthreadAttrGet(thread, &attr) == SCE_OK);
    Require(Scope(attr) == posix);
    Require(pthread_attr_destroy_nid_postfix(&attr) == 0);
    return posix;
}

static int CreatedScope(int inheritSched, int scope, bool defaultAttributes = false) {
    PthreadAttr attr = nullptr;
    Require(pthread_attr_init_nid_postfix(&attr) == 0);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, inheritSched) == 0);
    Require(pthread_attr_setscope_nid_postfix(&attr, scope) == 0);
    std::promise<void> release;
    auto released = release.get_future();
    Pthread thread = nullptr;
    Require(pthread_create_nid_postfix(&thread, defaultAttributes ? nullptr : &attr, Worker, &released) == 0);
    Require(pthread_attr_destroy_nid_postfix(&attr) == 0);
    const int reported = ThreadScope(thread, scope == SCOPE_SYSTEM ? SCOPE_PROCESS : SCOPE_SYSTEM);
    release.set_value();
    Require(pthread_join_nid_postfix(thread, nullptr) == 0);
    return reported;
}

static void* APS5_VABI InheritingCreator(void* arg) {
    auto& scopes = *static_cast<std::array<int, 3>*>(arg);
    scopes[0] = CreatedScope(INHERIT_SCHED, SCOPE_SYSTEM);
    scopes[1] = CreatedScope(EXPLICIT_SCHED, SCOPE_SYSTEM, true);
    scopes[2] = CreatedScope(EXPLICIT_SCHED, SCOPE_SYSTEM);
    return nullptr;
}

static void CheckThreadScope() {
    Require(CreatedScope(EXPLICIT_SCHED, SCOPE_PROCESS) == SCOPE_PROCESS);
    Require(CreatedScope(EXPLICIT_SCHED, SCOPE_SYSTEM) == SCOPE_SYSTEM);
    Require(CreatedScope(INHERIT_SCHED, SCOPE_PROCESS) == SCOPE_SYSTEM);
    Require(CreatedScope(EXPLICIT_SCHED, SCOPE_PROCESS, true) == SCOPE_SYSTEM);

    PthreadAttr attr = nullptr;
    Require(pthread_attr_init_nid_postfix(&attr) == 0);
    Require(pthread_attr_setinheritsched_nid_postfix(&attr, EXPLICIT_SCHED) == 0);
    Require(pthread_attr_setscope_nid_postfix(&attr, SCOPE_PROCESS) == 0);
    std::array<int, 3> inherited{-1, -1, -1};
    Pthread creator = nullptr;
    Require(pthread_create_nid_postfix(&creator, &attr, InheritingCreator, &inherited) == 0);
    Require(pthread_attr_destroy_nid_postfix(&attr) == 0);
    Require(pthread_join_nid_postfix(creator, nullptr) == 0);
    Require(inherited[0] == SCOPE_PROCESS);
    Require(inherited[1] == SCOPE_PROCESS);
    Require(inherited[2] == SCOPE_SYSTEM);
}

int main() {
    CheckSchedulingAttributes();
    CheckThreadScope();
    CheckStackSizeLimit();
    CheckSoloSched();
    PthreadAttr attr = nullptr;
    Require(scePthreadAttrInit(&attr) == SCE_OK);
    Require(scePthreadAttrSetinheritsched(&attr, EXPLICIT_SCHED) == SCE_OK);
    const KernelSchedParam requested{CREATION_PRIORITY};
    Require(scePthreadAttrSetschedparam(&attr, &requested) == SCE_OK);
    Require(scePthreadAttrSetaffinity(&attr, CREATION_AFFINITY) == SCE_OK);
    Require(scePthreadAttrSetstacksize(&attr, STACK_SIZE) == SCE_OK);

    std::promise<void> release;
    auto released = release.get_future();
    Pthread thread = nullptr;
    Require(scePthreadCreate(&thread, &attr, Worker, &released, nullptr) == SCE_OK);
    Require(scePthreadAttrDestroy(&attr) == SCE_OK);

    auto reported = Query(thread);
    Require(reported.priority == CREATION_PRIORITY);
    Require(reported.affinity == CREATION_AFFINITY);
    Require(reported.stackSize == STACK_SIZE);
    Require(reported.detachState == DETACH_JOINABLE);

    Require(scePthreadSetprio(thread, UPDATED_PRIORITY) == SCE_OK);
    Require(scePthreadSetaffinity(thread, UPDATED_AFFINITY) == SCE_OK);
    reported = Query(thread);
    Require(reported.priority == UPDATED_PRIORITY);
    Require(reported.affinity == UPDATED_AFFINITY);
    Require(reported.stackSize == STACK_SIZE);
    Require(reported.detachState == DETACH_JOINABLE);

    PthreadAttr destroyed = nullptr;
    Require(scePthreadAttrGet(thread, &destroyed) == SCE_KERNEL_ERROR_EINVAL);
    Require(scePthreadAttrGet(thread, nullptr) == SCE_KERNEL_ERROR_EINVAL);
    Require(scePthreadAttrInit(&attr) == SCE_OK);
    Require(scePthreadAttrGet(nullptr, &attr) == SCE_KERNEL_ERROR_EINVAL);
    Require(scePthreadAttrDestroy(&attr) == SCE_OK);

    release.set_value();
    Require(scePthreadJoin(thread, nullptr) == SCE_OK);

    PthreadAttr stackAttr = nullptr;
    char stackMarker;
    Require(pthread_attr_setstack_nid_postfix(nullptr, &stackMarker, STACK_SIZE) == 22);
    Require(pthread_attr_setstack_nid_postfix(&stackAttr, &stackMarker, STACK_SIZE) == 22);
    Require(scePthreadAttrInit(&stackAttr) == SCE_OK);
    Require(pthread_attr_setstack_nid_postfix(&stackAttr, &stackMarker, STACK_SIZE) == 0);
    Require(pthread_attr_setstack_nid_postfix(&stackAttr, nullptr, STACK_SIZE) == 22);
    Require(pthread_attr_setstack_nid_postfix(&stackAttr, &stackMarker, 16383) == 22);
    void* reportedAddress = nullptr;
    std::size_t reportedSize = 0;
    Require(pthread_attr_getstack_nid_postfix(&stackAttr, &reportedAddress, &reportedSize) == 0);
    Require(reportedAddress == &stackMarker && reportedSize == STACK_SIZE);
    Require(scePthreadAttrDestroy(&stackAttr) == SCE_OK);
    Require(pthread_attr_setstack_nid_postfix(&stackAttr, &stackMarker, STACK_SIZE) == 22);
}

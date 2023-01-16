#pragma once
#include <windows.h>

typedef NTSTATUS(NTAPI* PRTL_HEAP_COMMIT_ROUTINE)(
    _In_ PVOID Base,
    _Inout_ PVOID* CommitAddress,
    _Inout_ PSIZE_T CommitSize
    );

typedef struct _RTL_HEAP_PARAMETERS
{
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;

typedef PVOID(NTAPI* RTLCREATEHEAP)(
    _In_ ULONG Flags,
    _In_opt_ PVOID HeapBase,
    _In_opt_ SIZE_T ReserveSize,
    _In_opt_ SIZE_T CommitSize,
    _In_opt_ PVOID Lock,
    _In_opt_ PRTL_HEAP_PARAMETERS Parameters
    );

typedef PVOID(NTAPI* RTLALLOCATEHEAP)(
    _In_ PVOID  HeapHandle,
    _In_opt_ ULONG  Flags,
    _In_ SIZE_T Size
    );

typedef PVOID(NTAPI* RTLPROTECTHEAP)(
    _In_ PVOID HeapHandle,
    _In_ BOOLEAN Protect
    );

typedef BOOLEAN(NTAPI* RTLFREEHEAP)(
    IN PVOID HeapHandle,
    IN ULONG Flags OPTIONAL,
    IN PVOID MemoryPointer);

typedef NTSTATUS(NTAPI* RTLDESTROYHEAP)(
    _In_ PVOID HeapHandle
    );

typedef struct _PROTECTED_POLICY
{
    GUID guid;
    PDWORD64 flag;
} PROTECTED_POLICY, * PPROTECTED_POLICY;

typedef NTSTATUS(NTAPI* RTLQUERYPROTECTEDPOLICY)(
    LPCGUID guid,
    PULONG_PTR flag
    );

typedef NTSTATUS(NTAPI* RTLSETPROTECTEDPOLICY)(
    LPCGUID guid,
    ULONG  policy,
    PULONG_PTR flag
    );

typedef VOID(NTAPI* RTLRAISESTATUS)(IN NTSTATUS Status);

RTLCREATEHEAP RtlCreateHeap;
RTLALLOCATEHEAP RtlAllocateHeap;
RTLPROTECTHEAP RtlProtectHeap;
RTLFREEHEAP RtlFreeHeap;
RTLDESTROYHEAP RtlDestroyHeap;
RTLQUERYPROTECTEDPOLICY RtlQueryProtectedPolicy;
RTLSETPROTECTEDPOLICY RtlSetProtectedPolicy;
RTLRAISESTATUS RtlRaiseStatus;

// TODO: import from ntdll instead of kernel32
const auto RtlAcquireSRWLockExclusive = AcquireSRWLockExclusive;
const auto RtlReleaseSRWLockExclusive = ReleaseSRWLockExclusive;

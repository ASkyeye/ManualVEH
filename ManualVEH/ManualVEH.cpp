#include <iostream>
#include <Windows.h>
#include "VEH.h"
#include "ntos.h"
#include "ntrtl.h"

// CFG Stuff
PVOID LdrpAllocationGranularity = NULL;
PVOID LdrpMrdataHeap = NULL;
PVOID LdrpMrdataHeapUnprotected = NULL;
PVOID LdrpMrdataBase = NULL;
SRWLOCK LdrpMrdataLock;

SIZE_T LdrpMrdataSize;
int LdrpMrdataUnprotected;

// Used for RtlEncodePointer
ULONG g_CookieValue;


LONG CALLBACK MyVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	printf("[*] Hello from VEH!!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

LONG CALLBACK MyContinueHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	printf("[*] Hello from VCH!!\n");
	return EXCEPTION_CONTINUE_EXECUTION;
}

// https://cs.github.com/nccgroup/DetectWindowsCopyOnWriteForAPI/blob/7bb1a6f2a0b12fe342d6a762b64d11bfbb7b0f7e/d-vehlab/Engine.cpp#L189
PVOID GetLdrpVectorHandlerList() {
	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	if (ntdll == NULL)
		return 0;

	ULONGLONG procAddress = (ULONGLONG)GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler");
	BYTE* Buffer = (BYTE*)(GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler"));

	//fwprintf(stdout, TEXT("[*] RtlRemoveVectoredExceptionHandler [%llx]\n"), (procAddress));

	DWORD dwCount = 0;
	DWORD dwOffset = 0;
	for (dwCount = 0; dwCount < 60; dwCount++) {

		if ((*(Buffer + dwCount) == 0x4c) && (*(Buffer + dwCount + 1) == 0x8d) && (*(Buffer + dwCount + 2) == 0x25)) {
			memcpy(&dwOffset, (Buffer + dwCount + 3), 4);
			break;
		}
	}
	return (PVOID)(Buffer + dwCount + 7 + dwOffset);
}

__int64 LdrpLocateMrdata()
{
	printf("[*] LdrpLocateMrdata()\n");
	// TODO: still need to Reverse this func
	// For now we can just return the page that the VEH list is in (as a cheat)
	__int64 result = 0;

	PVOID addr = GetLdrpVectorHandlerList();
	MEMORY_BASIC_INFORMATION memInfo;

	if (!VirtualQuery(&addr, &memInfo, sizeof(memInfo)))
		__fastfail(5);

	LdrpMrdataBase = addr;
	LdrpMrdataSize = 0x1000;
	LdrpMrdataUnprotected = memInfo.Protect & PAGE_READONLY;

	//printf("[*] LdrpMrdataBase = %p\n", LdrpMrdataBase);
	//printf("[*] LdrpMrdataSize = %llu\n", LdrpMrdataSize);
	//printf("[*] LdrpMrdataUnprotected = %d\n", LdrpMrdataUnprotected);

	//__int64 v0; // rdx
	//__int64 v1; // rax
	//__int64 v2; // rdi
	//__int64 v3; // rbx
	//__int64 result; // rax
	//__int64 v5; // [rsp+30h] [rbp+8h] BYREF
	
	//RtlImageNtHeaderEx(3i64, 0x180000000ui64, 0i64, &v5);
	//v1 = RtlSectionTableFromVirtualAddress(v5, v0, (unsigned int)&LdrSystemDllInitBlock - 0x80000000);
	//if (!v1)
	//	__fastfail(5u);
	//v2 = 0x180000000i64 + *(unsigned int*)(v1 + 12);
	//v3 = *(unsigned int*)(v1 + 8);
	//result = LdrpMakePermanentImageCommit(v2, v3);
	//LdrpMrdataSize = v3;
	//LdrpMrdataBase = v2;
	return result;
}

NTSTATUS LdrpChangeMrdataProtection(ULONG Protect)
{
	NTSTATUS result;
	ULONG OldProtect;
	SIZE_T RegionSize;
	PVOID BaseAddress;

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	if (ntdll == NULL)
		return STATUS_INVALID_HANDLE;

	NtProtectVirtualMemory = (LPNTPROTECTVIRTUALMEMORY)GetProcAddress(ntdll, "NtProtectVirtualMemory");

	if (!LdrpMrdataBase)
		LdrpLocateMrdata();

	OldProtect = Protect;
	BaseAddress = LdrpMrdataBase;
	RegionSize = LdrpMrdataSize;

	//printf("[*] call NtProtectVirtualMemory\n");
	//printf("[*] Protect: %lu\n", Protect);
	//printf("[*] RegionSize: %zu\n", RegionSize);
	//printf("[*] BaseAddress: %p\n", BaseAddress);

	result = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, OldProtect, &OldProtect);
	//printf("[*] result = %d\n", result);

	if (!NT_SUCCESS(result))
		__fastfail(5);
	return result;
}

VOID NTAPI LdrProtectMrdata(int Protect)
{
	/*
	* Rules for calling this function (as I understand it)
	*
	* Calling LdrProtectMrdata(0) when LdrpMrdataUnprotected == 1 will cause a __fastfail
	* Calling LdrProtectMrdata(0) when LdrpMrdataUnprotected == -1 will cause a __fastfail
	* Calling LdrProtectMrdata(0) when LdrpMrdataUnprotected >= 1 will always increment LdrpMrdataUnprotected by 1
	* Calling LdrProtectMrdata(0) when LdrpMrdataUnprotected == 0 will:
		* cause the protection to be changed to READWRITE
		* increment LdrpMrdataUnprotected by 1
		* this means that LdrpMrdataUnprotected could be any value above 1, or even overflow (see above -1 check)
	*
	* Calling LdrProtectMrdata(1) when LdrpMrdataUnprotected == 0 will cause a __fastfail
	* Calling LdrProtectMrdata(1) when LdrpMrdataUnprotected > 0 will always decrement LdrpMrdataUnprotected by 1
	* Calling LdrProtectMrdata(1) when LdrpMrdataUnprotected == 1 will:
		* cause the protection to be changed to READONLY
		* decrement LdrpMrdataUnprotected by 1
	*
	* Notes:
	* a) you could crank up LdrpMrdataUnprotected to a high number and LdrProtectMrdata(1)
	*    will never actually set the page back to READONLY
	* b) the caller has to check LdrpMrdataUnprotected to make sure they dont crash the process if its out of sync
	* c) if LdrpMrdataUnprotected is uninitialised it will be treated as if the initial state is READONLY
	*/

	int isReadWrite; // edi

	printf("[*] LdrProtectMrdata(%d)\n", Protect);
	printf("[*] LdrpMrdataUnprotected: %d\n", LdrpMrdataUnprotected);

	RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
	isReadWrite = LdrpMrdataUnprotected;

	//LdrProtectMrdata(0)
	if (!Protect)
	{
		// If MrData is READONLY (LdrpMrdataUnprotected == 0)
		if (!LdrpMrdataUnprotected)
		{
			LdrpChangeMrdataProtection(PAGE_READWRITE);
		LABEL_5:
			LdrpMrdataUnprotected = isReadWrite + 1;
			return RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
		}
		// else it's already READWRITE (LdrpMrdataUnprotected > 0)

		// overflow check here
		// but what happens if it's 2 or already 1?
		if (LdrpMrdataUnprotected != -1)
			goto LABEL_5;
	LABEL_10:
		RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
		__fastfail(0xEu);
	}

	// LdrProtectMrData(1) ..

	// If MrData is READONLY (LdrpMrdataUnprotected == 0)
	// Shouldn't call LdrProtectMrdata(0) when LdrpMrdataUnprotected == 0
	if (!LdrpMrdataUnprotected)
		goto LABEL_10;

	// Decrement LdrpMrdataUnprotected (i.e. from 1 to 0)
	// But what happens if it was 2, does it go to 1?
	--LdrpMrdataUnprotected;

	// If LdrpMrdataUnprotected was originally 1 (i.e. READWRITE)
	// When we entered the function, then it's safe to change to READONLY
	if (isReadWrite == 1)
		LdrpChangeMrdataProtection(PAGE_READONLY);
	return RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
}

BOOL LdrControlFlowGuardEnforced()
{
	BOOL result = FALSE;

	/*
	DWORD64 qword_18018F3A8 = NULL;
	BYTE byte_18018F38C = NULL;

	if (!qword_18018F3A8)
		return FALSE;
	result = TRUE;
	if ((byte_18018F38C & 1) != 0)
		return FALSE;
	*/
	return result;
}

NTSTATUS LdrEnsureMrdataHeapExists()
{
	NTSTATUS result;
	PVOID pHeap;
	PVOID alloc;
	BOOLEAN ProtectHeap;
	PVOID BaseAddress;
	ULONG_PTR RegionSize;

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	if (ntdll == NULL)
		return STATUS_INVALID_HANDLE;

	NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	NtFreeVirtualMemory = (LPNTFREEVIRTUALMEMORY)GetProcAddress(ntdll, "NtFreeVirtualMemory");
	RtlCreateHeap = (RTLCREATEHEAP)GetProcAddress(ntdll, "RtlCreateHeap");
	RtlAllocateHeap = (RTLALLOCATEHEAP)GetProcAddress(ntdll, "RtlAllocateHeap");
	RtlProtectHeap = (RTLPROTECTHEAP)GetProcAddress(ntdll, "RtlProtectHeap");
	RtlFreeHeap = (RTLFREEHEAP)GetProcAddress(ntdll, "RtlFreeHeap");
	RtlDestroyHeap = (RTLDESTROYHEAP)GetProcAddress(ntdll, "RtlDestroyHeap");

	printf("[*] LdrEnsureMrdataHeapExists\n");

	// If CFG is not enabled or LdrpMrdataHeap has already been allocated (i.e. not NULL)
	if (!LdrControlFlowGuardEnforced() || LdrpMrdataHeap)
		return STATUS_SUCCESS;

	BaseAddress = 0;
	RegionSize = (ULONG_PTR)LdrpAllocationGranularity;

	result = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_RESERVE, PAGE_READWRITE);

	if (NT_SUCCESS(result))
	{
		pHeap = RtlCreateHeap(HEAP_GROWABLE, BaseAddress, 0, 0, 0, 0);

		if (pHeap)
		{
			alloc = RtlAllocateHeap(pHeap, 0, 4);

			if (alloc)
			{
				ProtectHeap = TRUE;
				RtlProtectHeap(pHeap, ProtectHeap);
				LdrProtectMrdata(FALSE);
				RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
				// Now we allocated a READONLY heap, lets update the global variables
				if (!LdrpMrdataHeap)
				{
					// LdrpMrdataHeapUnprotected will either be NULL or address of alloc
					LdrpMrdataHeapUnprotected = alloc;
					LdrpMrdataHeap = pHeap;
					RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
					LdrProtectMrdata(TRUE);
					return STATUS_SUCCESS;
				}
				RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
				LdrProtectMrdata(TRUE);
				RtlProtectHeap(pHeap, 0);
				RtlFreeHeap(pHeap, 0, alloc);
			}
			RtlDestroyHeap(pHeap);
		}

		// Free memory we allocated with NtAllocateVirtualMemory
		// We get here if RtlCreateHeap or RtlAllocateHeap failed
		NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);

		// Should always hit STATUS_NO_MEMORY here, since we never successfully called RtlAllocateHeap
		// However another thread may have already allocated it, so we double check (I guess?)
		if (!LdrpMrdataHeap)
			return STATUS_NO_MEMORY;
		return STATUS_SUCCESS;
	}
	// If NtAllocateVirtualMemory fails, we just return it's NT_STATUS
	return result;
}

PPEB NtCurrentPeb()
{
#if defined(_WIN64)
	PPEB peb = (PPEB)__readgsqword(0x60);
#else
	PPEB peb = (PPEB)__readfsdword(0x30);
#endif
	return peb;
}

PVECTORED_HANDLER_ENTRY RtlpAddVectoredHandler(
	IN ULONG FirstHandler,
	IN PVECTORED_EXCEPTION_HANDLER VectoredHandler,
	IN BOOL IsUsingVCH)
{
	bool v15;
	DWORD checked;

	PVOID pHeap;
	PVOID ProcessHeap;
	PVOID alloc1;
	
	VECTORED_HANDLER_ENTRY* newEntry;
	
	LIST_ENTRY* Flink;
	LIST_ENTRY* Blink;
	
	DWORD isLdrpMrdataHeapUnprotected;
	BOOLEAN Protect;
	NTSTATUS status;
	ULONG cookie = 0;
	DWORD64 policyEnabled = 0;

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	if (ntdll == 0)
		return NULL;

	NtQueryInformationProcess = (LPNTQUERYINFORMATIONPROCESS)GetProcAddress(ntdll, "NtQueryInformationProcess");
	RtlQueryProtectedPolicy = (RTLQUERYPROTECTEDPOLICY)GetProcAddress(ntdll, "RtlQueryProtectedPolicy");
	RtlRaiseStatus = (RTLRAISESTATUS)GetProcAddress(ntdll, "RtlRaiseStatus");
	RtlAllocateHeap = (RTLALLOCATEHEAP)GetProcAddress(ntdll, "RtlAllocateHeap");
	RtlProtectHeap = (RTLPROTECTHEAP)GetProcAddress(ntdll, "RtlProtectHeap");
	RtlFreeHeap = (RTLFREEHEAP)GetProcAddress(ntdll, "RtlFreeHeap");

	printf("[*] RtlpAddVectoredHandler\n");

	// 1fc98bca-1ba9-4397-93f9-349ead41e057
	GUID guid = { 0x1fc98bca, 0x1ba9, 0x4397, {0x93, 0xf9, 0x34, 0x9e, 0xad, 0x41, 0xe0, 0x57} };

	if (NT_SUCCESS(LdrEnsureMrdataHeapExists()) && RtlQueryProtectedPolicy(&guid, &policyEnabled) || !policyEnabled)
	{
		printf("[*] ProtectedPolicy == FALSE\n");

		if (LdrControlFlowGuardEnforced())
		{
			printf("[*] LdrControlFlowGuardEnforced == TRUE\n");

			RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
			checked = *(DWORD*)LdrpMrdataHeapUnprotected;
			if (*(DWORD*)LdrpMrdataHeapUnprotected)
			{
				// Seems like an overflow check
				if (checked == -1)
					goto RELEASE_LDRPDATALOCK_AND_FAIL_WITH_ERROR_14;
			}
			else
			{
				// Make LdrpMrdataHeap PAGE_READWRITE
				RtlProtectHeap(LdrpMrdataHeap, 0);
			}

			// Sets LdrpMrdataHeapUnprotected = TRUE
			*(DWORD*)LdrpMrdataHeapUnprotected = checked + 1;
			RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
		}

		// ProcessHeap should be READWRITE now
		if (LdrControlFlowGuardEnforced())
			ProcessHeap = LdrpMrdataHeap;
		else
			ProcessHeap = NtCurrentPeb()->ProcessHeap;

		// Allocate Heap to store new VECTORED_HANDLER_ENTRY structure
		//printf("[*] sizeof(VECTORED_HANDLER_ENTRY) == %zu\n", sizeof(VECTORED_HANDLER_ENTRY));
		newEntry = (VECTORED_HANDLER_ENTRY*)RtlAllocateHeap(ProcessHeap, 0, sizeof(VECTORED_HANDLER_ENTRY));
		printf("[*] Allocated newEntry at: %p\n", newEntry);

		// If RtlAllocateHeap failed ..
		if (!newEntry)
		{
		RESTORE_MRDATAHEAP_PROTECTION_AND_RETURN:
			// Just return pVecNewEntry if CFG was already disabled
			if (!LdrControlFlowGuardEnforced())
				return newEntry;

			// otherwise re-enable LdrpMrdataHeap Protection first
			RtlAcquireSRWLockExclusive(&LdrpMrdataLock);
			isLdrpMrdataHeapUnprotected = *(DWORD*)LdrpMrdataHeapUnprotected;

			if (LdrpMrdataHeapUnprotected)
			{
				v15 = isLdrpMrdataHeapUnprotected == 1;
				Protect = (unsigned int)(isLdrpMrdataHeapUnprotected - 1);
				*(DWORD*)LdrpMrdataHeapUnprotected = Protect;
				if (v15)
				{
					Protect = 1;
					RtlProtectHeap(LdrpMrdataHeap, Protect);
				}
				RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
				return newEntry;
			}

		RELEASE_LDRPDATALOCK_AND_FAIL_WITH_ERROR_14:
			RtlReleaseSRWLockExclusive(&LdrpMrdataLock);
			__fastfail(0xE);
		}

		// Reserved: Always 0
		newEntry->Unknown2 = 0;

		// Allocate heap space and store the address in pVecNewEntry->Unknown1
		alloc1 = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, sizeof(ULONG));
		newEntry->Unknown1 = (ULONG*)alloc1;

		if (!alloc1)
		{
			// If RtlAllocateHeap failed then free LdrpMrdataHeap / ProcessHeap
			// and then return NULL
			if (LdrControlFlowGuardEnforced())
				pHeap = LdrpMrdataHeap;
			else
				pHeap = NtCurrentPeb()->ProcessHeap;

			RtlFreeHeap(pHeap, 0, newEntry);
			newEntry = NULL;
			goto RESTORE_MRDATAHEAP_PROTECTION_AND_RETURN;
		}

		*(ULONG*)alloc1 = 1;
		printf("[*] pVecNewEntry->Unknown1: %d\n", *newEntry->Unknown1);

		if (!g_CookieValue)
		{
			status = NtQueryInformationProcess(
				(HANDLE)0xFFFFFFFFFFFFFFFF,
				(PROCESSINFOCLASS)36,
				&cookie,
				sizeof(ULONG),
				NULL);

			if (status < 0)
				RtlRaiseStatus(status);

			g_CookieValue = cookie;
			printf("[*] Cookie: %lu\n", cookie);
		}

		// Encode the Handler pointer using the process cookie value
		newEntry->Handler = (PVECTORED_EXCEPTION_HANDLER)_rotr64((ULONG_PTR)VectoredHandler ^ cookie, cookie & 0x3F);

		// FIXME: not working with VCH
		PVECTORED_HANDLER_LIST LdrpVectorHandlerList = (PVECTORED_HANDLER_LIST)GetLdrpVectorHandlerList();
		PVECTORED_HANDLER_LIST head = &LdrpVectorHandlerList[IsUsingVCH];

		printf("[*] LdrpVectorHandlerList = %llx\n", *(ULONG_PTR*)LdrpVectorHandlerList);
		printf("[*] head = %p\n", &head);
		printf("[*] head->SrwLock = %p\n", head->SrwLock);
		printf("[*] head->HandlerList = %p\n", &head->HandlerList);

		// Unprotect .mrdata and acquire the LdrpVectorHandlerList VEH/VCH SRW lock
		LdrProtectMrdata(0);
		RtlAcquireSRWLockExclusive(head->SrwLock);

		// Add correct bitmask to NtCurrentPeb()->CrossProcessFlags for VEH/VCH if list was previously empty ..
		if (head->HandlerList.Flink == &head->HandlerList)
		{
			BOOL status = _interlockedbittestandset((LONG*)((PBYTE)NtCurrentPeb() + 0x50), IsUsingVCH + 2);
			printf("[*] _interlockedbittestandset: %d\n", status);
		}

		printf("[*] NtCurrentPeb()->CrossProcessFlags: %d\n", *(LONG*)((PBYTE)NtCurrentPeb() + 0x50));

		if (FirstHandler)
		{
			printf("[*] Adding First Handler\n");
			printf("[*] Flink = %p\n", head->HandlerList.Flink);
			printf("[*] Blink = %p\n", head->HandlerList.Blink);
			printf("[*] head->HandlerList = %p\n", &head->HandlerList);

			if (head->HandlerList.Flink->Blink == &head->HandlerList)
			{
				printf("[*] address of newEntry: %p\n", newEntry);
				Flink = head->HandlerList.Flink;
				newEntry->Entry.Flink = Flink;
				newEntry->Entry.Blink = &head->HandlerList;
				Flink->Blink = &newEntry->Entry;
				head->HandlerList.Flink = &newEntry->Entry;
				RtlReleaseSRWLockExclusive(head->SrwLock);
				LdrProtectMrdata(1);
				goto RESTORE_MRDATAHEAP_PROTECTION_AND_RETURN;
			}
		}
		else
		{
			printf("[*] Adding Last Handler\n");
			printf("[*] Flink = %p\n", head->HandlerList.Flink);
			printf("[*] Blink = %p\n", head->HandlerList.Blink);
			printf("[*] head->HandlerList = %p\n", &head->HandlerList);

			Blink = head->HandlerList.Blink;
			if (Blink->Flink == &head->HandlerList)
			{
				printf("[*] address of newEntry: %p\n", newEntry);
				newEntry->Entry.Flink = &head->HandlerList;
				newEntry->Entry.Blink = Blink;
				Blink->Flink = &newEntry->Entry;
				head->HandlerList.Blink = &newEntry->Entry;
				RtlReleaseSRWLockExclusive(head->SrwLock);
				LdrProtectMrdata(1);
				goto RESTORE_MRDATAHEAP_PROTECTION_AND_RETURN;
			}
		}
		__fastfail(3);
	}
	return NULL;
}

VECTORED_HANDLER_ENTRY* RtlAddVectoredExceptionHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
	return RtlpAddVectoredHandler(FirstHandler, VectoredHandler, FALSE);
}

VECTORED_HANDLER_ENTRY* RtlAddVectoredContinueHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
{
	return RtlpAddVectoredHandler(FirstHandler, VectoredHandler, TRUE);
}

void DumpHandlerList(PVECTORED_HANDLER_LIST head)
{
	PLIST_ENTRY Flink = head->HandlerList.Flink;
	int count = 0;

	printf("head->SrwLock:			%p\n", head->SrwLock);
	printf("head->Entry:			%p\n", &head->HandlerList);
	printf("head->Entry->Flink:		%p\n", head->HandlerList.Flink);
	printf("head->Entry->Blink:		%p\n", head->HandlerList.Blink);

	for (PLIST_ENTRY next = Flink; next != &head->HandlerList && count < 255; next = next->Flink)
	{
		PVECTORED_HANDLER_ENTRY entry = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(next);
		printf("-->\n");
		printf("entry #%d\n", count+1);
		printf("entry->Entry:			%p\n", &entry->Entry);
		printf("entry->Entry.Flink:		%p\n", entry->Entry.Flink);
		printf("entry->Unknown1:		%lu\n", *entry->Unknown1);
		printf("entry->Unknown2:		%lu\n", entry->Unknown2);
		printf("entry->Handler:			%p (decoded)\n", DecodePointer(entry->Handler));
		count++;
	}
}

void DumpHandlers(BOOL addVEH, BOOL addVCH)
{
	VECTORED_HANDLER_ENTRY* veh = NULL;
	VECTORED_HANDLER_ENTRY* vch = NULL;
	VECTORED_HANDLER_LIST* LdrpVectorHandlerList = (PVECTORED_HANDLER_LIST)GetLdrpVectorHandlerList();

	printf("\n----------------------------------------------------------------\n");
	printf(" *** Metadata ***\n");
	printf("----------------------------------------------------------------\n");

	if (addVEH)
	{
		veh = (VECTORED_HANDLER_ENTRY*)AddVectoredExceptionHandler(1, MyVectoredHandler);
		printf("Added VEH via AddVectoredExceptionHandler()\n");
		printf("Address of VEH:			%p\n", veh);
	}

	if (addVCH)
	{
		vch = (VECTORED_HANDLER_ENTRY*)AddVectoredContinueHandler(1, MyContinueHandler);
		printf("Added VCH via AddVectoredContinueHandler()\n");
		printf("Address of VCH:			%p\n", vch);
	}

	printf("MyVectoredHandler:		%p\n", MyVectoredHandler);
	printf("MyContinueHandler:		%p\n", MyContinueHandler);
	printf("LdrpVectorHandlerList:		0x%llx\n", *(ULONG_PTR*)LdrpVectorHandlerList);

	//if (addVEH && veh != NULL)
	//{
	//	printf("veh = AddVectoredExceptionHandler(1, MyVectoredHandler):\n");
	//	printf("veh->Entry:				%p\n", &veh->Entry);
	//	printf("veh->Entry.Flink:			%p\n", vehEntry->Entry.Flink);
	//	printf("veh->Unknown1:				%lu\n", *veh->Unknown1);
	//	printf("veh->Unknown2:				%lu\n", veh->Unknown2);
	//	printf("veh->Handler:				%p (decoded)\n", DecodePointer(veh->Handler));
	//  RemoveVectoredExceptionHandler(veh);
	//}

	//if (addVCH && vch != NULL)
	//{
	//	printf("vch = AddVectoredContinueHandler(1, MyContinueHandler):\n");
	//	printf("vch->Entry:				%p\n", &vch->Entry);
	//	printf("vch->Unknown1:				%lu\n", *vch->Unknown1);
	//	printf("vch->Unknown2:				%lu\n", vch->Unknown2);
	//	printf("vch->Handler:				%p\n", vch->Handler);
	//	printf("vch->Handler:				%p (decoded)\n", DecodePointer(vch->Handler));
	//  RemoveVectoredContinueHandler(vch);
	//}

	printf("\n----------------------------------------------------------------\n");
	printf(" *** Vectored Exception Handlers ***\n");
	printf("----------------------------------------------------------------\n");
	DumpHandlerList(&LdrpVectorHandlerList[0]);

	printf("\n----------------------------------------------------------------\n");
	printf(" *** Vectored Continue Handlers ***\n");
	printf("----------------------------------------------------------------\n");
	DumpHandlerList(&LdrpVectorHandlerList[1]);
	printf("\n");
}

void TestHandlers() {
	printf("[*] Adding VEH in PID: %d\n", GetCurrentProcessId());
	printf("[*] Should see Hello ..\n");
	PVOID veh = AddVectoredExceptionHandler(1, MyVectoredHandler);
	RaiseException(0x123, 0, 0, 0);
	RemoveVectoredExceptionHandler(veh);
}

void TestProtectedPolicy(BOOL enable)
{
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	if (ntdll == 0)
		return;

	RtlQueryProtectedPolicy = (RTLQUERYPROTECTEDPOLICY)GetProcAddress(ntdll, "RtlQueryProtectedPolicy");
	RtlSetProtectedPolicy = (RTLSETPROTECTEDPOLICY)GetProcAddress(ntdll, "RtlSetProtectedPolicy");

	GUID guid = { 0x1fc98bca, 0x1ba9, 0x4397, {0x93, 0xf9, 0x34, 0x9e, 0xad, 0x41, 0xe0, 0x57} };
	DWORD64 flag;

	if (NT_SUCCESS(RtlQueryProtectedPolicy(&guid, &flag)))
		printf("[*] Old ProtectedPolicy: %zu\n", flag);

	if (enable && NT_SUCCESS(RtlSetProtectedPolicy(&guid, 1, &flag)))
		printf("[*] Set policy: %zu\n", flag);

	if (enable && NT_SUCCESS(RtlQueryProtectedPolicy(&guid, &flag)))
		printf("[*] New ProtectedPolicy: %zu\n", flag);
}

void SetProtect(int i)
{
	LdrProtectMrdata(i);
	printf("[*] LdrpMrdataUnprotected: %d\n", LdrpMrdataUnprotected);
}

void TestLdrpChangeMrdataProtection()
{
	LdrpLocateMrdata();
	SetProtect(0);
}

void TestRtlpAddHandlers()
{
	printf("[+] Running in proc: %d\n", GetCurrentProcessId());
	PVOID veh = RtlAddVectoredExceptionHandler(0, MyVectoredHandler);
	//PVOID vch = RtlAddVectoredContinueHandler(1, MyContinueHandler);
	//RaiseException(0x123, 0, 0, 0);
	void* alloc = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY | PAGE_GUARD);
	DWORD test = 1;
	//memcpy(alloc, &test, 1);
	DumpHandlers(FALSE, FALSE);
	RemoveVectoredExceptionHandler(veh);
	//RemoveVectoredContinueHandler(vch);
}

int main()
{
	// TODO:
	// RtlAddVectoredContinueHandler doesn't work when calling RaiseException
	// There's no implementation of RtlpRemoveVectoredHandler yet
	// Doesn't work with CFG yet, need to implement some more of the Ldr functions
	// Need to clean up the PEB.h header so it plays nicely with winternl.h
 	// Figure out how we can use ROP to avoid allocating RX memory ourselves
	// Implement direct syscalls for Nt functions (e.g. NtProtectVirtualMemory)
	// Need to implement RemoteRtlAddVectoredExceptionHandler and RemoteRtlAddVectoredContinueHandler ;)
	// Convert to a BOF \o/
	TestRtlpAddHandlers();
}

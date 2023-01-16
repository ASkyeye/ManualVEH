#pragma once

// https://www.unknowncheats.me/forum/2850461-post17.html

// size = 40 bytes
typedef struct _VECTORED_HANDLER_ENTRY
{
    LIST_ENTRY Entry;
    ULONG* Unknown1;
    ULONG Unknown2;
    PVECTORED_EXCEPTION_HANDLER Handler;
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

// size = 24 bytes
typedef struct _VECTORED_HANDLER_LIST
{
    PSRWLOCK SrwLock;   // 8 bytes
    LIST_ENTRY HandlerList;   // 16 bytes
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

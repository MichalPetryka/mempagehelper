#include "mempagehelper.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#if MEMPAGEHELPER_WINDOWS
#include <Windows.h>
#else
#include <unistd.h>
#include <errno.h>
#endif

static_assert(sizeof(size_t) == sizeof(uintptr_t), "Only platforms with ptr sized size are supported!");

thread_local static uint32_t last_error = 0;
static uint32_t page_size_cache = 0;
#if MEMPAGEHELPER_WINDOWS
static uint32_t page_alloc_granularity_cache = 0;
#endif

MEMPAGEHELPER_INTERNAL(void) fetch_sys_info()
{
#if MEMPAGEHELPER_WINDOWS
	SYSTEM_INFO info = {};
	GetSystemInfo(&info);
	page_size_cache = info.dwPageSize;
	page_alloc_granularity_cache = info.dwAllocationGranularity;
#else
	page_size_cache = getpagesize();
#endif
}

uint32_t page_size()
{
	if (page_size_cache != 0)
		return page_size_cache;

	fetch_sys_info();
	return page_size_cache;
}

uint32_t page_alloc_granularity()
{
#if MEMPAGEHELPER_WINDOWS
#define granularity_cache page_alloc_granularity_cache
#else
#define granularity_cache page_size_cache
#endif
	if (granularity_cache != 0)
		return granularity_cache;

	fetch_sys_info();
	return granularity_cache;
#undef granularity_cache
}

#pragma warning( push )
#pragma warning( disable : 4100 )
int32_t page_free(void* memory, size_t size)
{
#if MEMPAGEHELPER_WINDOWS
	if (!VirtualFree(memory, 0, MEM_RELEASE))
	{
		last_error = GetLastError();
#else
	if (munmap(memory, size) != 0)
	{
		last_error = (uint32_t)errno;
#endif
		return 1;
	}
	last_error = 0;
	return 0;
}
#pragma warning( pop )

#if MEMPAGEHELPER_WINDOWS
#define PROTECTION_TYPE DWORD
#define INVALID_PARAM ERROR_INVALID_PARAMETER
#else
#define PROTECTION_TYPE int
#define INVALID_PARAM EINVAL
#endif

MEMPAGEHELPER_INTERNAL(bool) convert_protection(PAGE_ACCESS access, PROTECTION_TYPE * protection)
{
	assert(protection != NULL);
	PROTECTION_TYPE protect;

#if MEMPAGEHELPER_WINDOWS
#pragma warning( push )
#pragma warning( disable : 4063 )
	switch (access) {
	case PAGE_ACCESS_NONE:
		protect = PAGE_NOACCESS;
		break;
	case PAGE_ACCESS_READ:
		protect = PAGE_READONLY;
		break;
	case PAGE_ACCESS_EXECUTE:
		protect = PAGE_EXECUTE;
		break;
	case PAGE_ACCESS_READ | PAGE_ACCESS_WRITE:
		protect = PAGE_READWRITE;
		break;
	case PAGE_ACCESS_READ | PAGE_ACCESS_EXECUTE:
		protect = PAGE_EXECUTE_READ;
		break;
	case PAGE_ACCESS_READ | PAGE_ACCESS_WRITE | PAGE_ACCESS_EXECUTE:
		protect = PAGE_EXECUTE_READWRITE;
		break;
	default:
		return false;
	}
#pragma warning( pop )
#else
	protect = PROT_NONE;
	if (access & ~(PAGE_ACCESS_READ | PAGE_ACCESS_WRITE | PAGE_ACCESS_EXECUTE))
		return false;

	if (access & PAGE_ACCESS_READ)
		protect |= PROT_READ;
	if (access & PAGE_ACCESS_WRITE)
		protect |= PROT_WRITE;
	if (access & PAGE_ACCESS_EXECUTE)
		protect |= PROT_EXEC;
#endif

	*protection = protect;
	return true;
}

void* page_alloc(size_t size, PAGE_ACCESS access)
{
	PROTECTION_TYPE protect;
	if (!convert_protection(access, &protect))
	{
		last_error = INVALID_PARAM;
		return NULL;
	}

	void* addr;
#if MEMPAGEHELPER_WINDOWS
	addr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
	if (addr == NULL)
	{
		last_error = GetLastError();
#else

#ifndef MAP_UNINITIALIZED
#define MAP_UNINITIALIZED 0
#endif

	addr = mmap(NULL, size, protect, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
	if (addr == MAP_FAILED)
	{
		last_error = (uint32_t)errno;
#endif
		return NULL;
	}
	last_error = 0;
	return addr;
}

int32_t page_change_access(void* memory, size_t size, PAGE_ACCESS access)
{
	PROTECTION_TYPE protect;
	if (!convert_protection(access, &protect))
	{
		last_error = INVALID_PARAM;
		return 1;
	}

#if MEMPAGEHELPER_WINDOWS
	DWORD old_protect;
	if (!VirtualProtect(memory, size, protect, &old_protect))
	{
		last_error = GetLastError();
#else
	if (mprotect(memory, size, protect) != 0)
	{
		last_error = (uint32_t)errno;
#endif
		return 1;
	}
	last_error = 0;
	return 0;
}

int32_t page_lock(void* memory, size_t size)
{
#if MEMPAGEHELPER_WINDOWS
	if (!VirtualLock(memory, size))
	{
		last_error = GetLastError();
#else
	if (mlock(memory, size) != 0)
	{
		last_error = (uint32_t)errno;
#endif
		return 1;
	}
	last_error = 0;
	return 0;
}

int32_t page_unlock(void* memory, size_t size)
{
#if MEMPAGEHELPER_WINDOWS
	if (!VirtualUnlock(memory, size))
	{
		last_error = GetLastError();
#else
	if (munlock(memory, size) != 0)
	{
		last_error = (uint32_t)errno;
#endif
		return 1;
	}
	last_error = 0;
	return 0;
}

int32_t page_flush_instructions(void* memory, size_t size)
{
#if MEMPAGEHELPER_WINDOWS
	if (!FlushInstructionCache(GetCurrentProcess(), memory, size))
	{
		last_error = GetLastError();
		return 1;
	}
	last_error = 0;
	return 0;
#else
	__builtin___clear_cache((char*)memory, ((char*)memory) + size);
	return 0;
#endif
}

uint32_t page_last_error()
{
	return last_error;
}

#define ERROR_BUFFER_SIZE (64 * 1024)

MEMPAGEHELPER_SYSCHAR* page_error_message_sys(uint32_t error)
{
	MEMPAGEHELPER_SYSCHAR* buffer = (MEMPAGEHELPER_SYSCHAR*)malloc(ERROR_BUFFER_SIZE);
#if MEMPAGEHELPER_WINDOWS
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, buffer, ERROR_BUFFER_SIZE, NULL) == 0)
	{
		free(buffer);
		return NULL;
	}
#elif (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
	int code = strerror_r((int)error, buffer, ERROR_BUFFER_SIZE);
	if (code != 0)
	{
		free(buffer);
		return NULL;
	}
#else
	char* message = strerror_r((int)error, buffer, ERROR_BUFFER_SIZE);
	if (message != buffer)
	{
		size_t len = strlen(message);
		if (len > size - 2)
		{
			free(buffer);
			return NULL;
		}

		memcpy(buffer, message, len);
		buffer[len] = 0;
	}
#endif
	return buffer;
}

unsigned char* page_error_message_utf8(uint32_t error)
{
#if MEMPAGEHELPER_WINDOWS
	MEMPAGEHELPER_SYSCHAR* ptr = page_error_message_sys(error);
	if (ptr == NULL)
	{
		return NULL;
	}
	size_t len = wcslen(ptr);
	unsigned char* buffer = (unsigned char*)malloc(len * 3);
	int out_len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, (int)len, (LPSTR)buffer, (int)(len * 3 - 1), NULL, NULL);
	free(ptr);

	if (out_len <= 0)
		return NULL;

	buffer[out_len] = 0;
	return buffer;
#else
	return page_error_message_sys(error);
#endif
}

void page_error_free(void* message)
{
	free(message);
}

uint32_t page_lib_version()
{
	return MEMPAGEHELPER_VERSION;
}

#include "mempagehelper.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#ifndef __STDC_NO_THREADS__
#include <threads.h>
#endif
#if MEMPAGEHELPER_WINDOWS
#include <Windows.h>
#else
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#endif

static_assert(sizeof(size_t) == sizeof(uintptr_t), "Only platforms with ptr sized size are supported!");

#ifdef __STDC_NO_THREADS__
static __thread uint32_t last_error = 0;
#else
thread_local static uint32_t last_error = 0;
#endif

static uint32_t page_size_cache = 0;
#if MEMPAGEHELPER_WINDOWS
static uint32_t page_alloc_granularity_cache = 0;
#endif

#ifndef MEMPAGEHELPER_TRACKING
static void* error_cache = NULL;
#endif

MEMPAGEHELPER_INTERNAL(void) fetch_sys_info(void)
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

uint32_t page_size(void)
{
	if (page_size_cache != 0)
		return page_size_cache;

	fetch_sys_info();
	return page_size_cache;
}

uint32_t page_alloc_granularity(void)
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

#if MEMPAGEHELPER_WINDOWS
#define PROTECTION_TYPE DWORD
#define INVALID_PARAM ERROR_INVALID_PARAMETER
#else
#define PROTECTION_TYPE int
#define INVALID_PARAM EINVAL
#endif

MEMPAGEHELPER_INTERNAL(bool) convert_protection(uint32_t access, PROTECTION_TYPE* protection)
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

#ifdef MEMPAGEHELPER_TRACKING
MEMPAGEHELPER_INTERNAL(void) change_access(void* page, uint32_t access, uint32_t old_access)
{
	PROTECTION_TYPE protection = 0;
	bool converted = convert_protection(access, &protection);
	assert(converted);
	PROTECTION_TYPE old_protection = 0;
	converted = convert_protection(old_access, &old_protection);
	assert(converted);
#if MEMPAGEHELPER_WINDOWS
	DWORD old_protect = 0;
	VirtualProtect(page, page_size(), protection, &old_protect);
	assert(old_protect == old_protection);
#else
	if (old_access & PAGE_ACCESS_READ)
	{
		size_t test_data = 0;
		memcpy(&test_data, page, sizeof(size_t));
		assert(test_data != 0);
	}
	mprotect(page, page_size(), protection);
#endif
}

MEMPAGEHELPER_INTERNAL(void*) mark_memory(void* memory, size_t size, uint32_t alloc_access)
{
	assert(memory != NULL);
	uint32_t page = page_size();
	assert((uintptr_t)memory % page == 0);
	memcpy(memory, &size, sizeof(size_t));
	memcpy((unsigned char*)memory + page - 32, "Memory start validation string!?", 32);
	change_access(memory, PAGE_ACCESS_NONE, alloc_access);
	memory = (unsigned char*)memory + page;

	size_t real_size = size;
	size_t last_page_content = size % page;
	if (last_page_content != 0)
	{
		size_t check_size = page - last_page_content;
		if (check_size > 32)
			check_size = 32;
		memcpy((unsigned char*)memory + size, "End of memory string validation!", check_size);
		real_size += page - last_page_content;
	}
	unsigned char* end = (unsigned char*)memory + real_size;
	memcpy(end, "After alloc check text message!?", 32);
	change_access(end, PAGE_ACCESS_NONE, alloc_access);
	return memory;
}

MEMPAGEHELPER_INTERNAL(void) validate_memory(void* memory, size_t size)
{
	assert(memory != NULL);
	uint32_t page = page_size();
	assert((uintptr_t)memory % page == 0);
	unsigned char* real_start = (unsigned char*)memory - page;
	change_access(real_start, PAGE_ACCESS_READ, PAGE_ACCESS_NONE);
	size_t real_size = 0;
	memcpy(&real_size, real_start, sizeof(size_t));
	assert(size == real_size);
	assert(memcmp((unsigned char*)memory - 32, "Memory start validation string!?", 32) == 0);
	change_access(real_start, PAGE_ACCESS_NONE, PAGE_ACCESS_READ);
	size_t last_page_content = size % page;
	if (last_page_content != 0)
	{
		size_t check_size = page - last_page_content;
		if (check_size > 32)
			check_size = 32;
		assert(memcmp((unsigned char*)memory + size, "End of memory string validation!", check_size) == 0);
		real_size += page - last_page_content;
	}
	unsigned char* end = (unsigned char*)memory + real_size;
	change_access(end, PAGE_ACCESS_READ, PAGE_ACCESS_NONE);
	assert(memcmp(end, "After alloc check text message!?", 32) == 0);
	change_access(end, PAGE_ACCESS_NONE, PAGE_ACCESS_READ);
}
#endif


#if MEMPAGEHELPER_WINDOWS
#pragma warning( push )
#pragma warning( disable : 4100 )
#endif
int32_t page_free(void* memory, size_t size)
{
#ifdef MEMPAGEHELPER_TRACKING
	validate_memory(memory, size);
	uint32_t page = page_size();
	memory = (unsigned char*)memory - page;
	size += page * 2;
#endif

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
#if MEMPAGEHELPER_WINDOWS
#pragma warning( pop )
#endif

void* page_alloc(size_t size, uint32_t access)
{
	PROTECTION_TYPE protect;
#ifdef MEMPAGEHELPER_TRACKING
	uint32_t alloc_access = access | PAGE_ACCESS_READ | PAGE_ACCESS_WRITE;
#else
	uint32_t alloc_access = access;
#endif
	if (!convert_protection(alloc_access, &protect))
	{
		last_error = INVALID_PARAM;
		return NULL;
	}

#ifdef MEMPAGEHELPER_TRACKING
	uint32_t page = page_size();
	size_t alloc_size = size + page * 2;
#else
	size_t alloc_size = size;
#endif

	void* addr;
#if MEMPAGEHELPER_WINDOWS
	addr = VirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, protect);
	if (addr == NULL)
	{
		last_error = GetLastError();
#else

#ifndef MAP_UNINITIALIZED
#define MAP_UNINITIALIZED 0
#endif

	addr = mmap(NULL, alloc_size, protect, MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNINITIALIZED, -1, 0);
	if (addr == MAP_FAILED)
	{
		last_error = (uint32_t)errno;
#endif
		return NULL;
	}

#ifdef MEMPAGEHELPER_TRACKING
	addr = mark_memory(addr, size, alloc_access);

	if (access != (PAGE_ACCESS_READ | PAGE_ACCESS_WRITE) && page_change_access(addr, size, access) != 0)
	{
		page_free(addr, size);
		return NULL;
	}
#endif

	last_error = 0;
	return addr;
}

int32_t page_change_access(void* memory, size_t size, uint32_t access)
{
#ifdef MEMPAGEHELPER_TRACKING
	validate_memory(memory, size);
#endif

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
#ifdef MEMPAGEHELPER_TRACKING
	validate_memory(memory, size);
#endif

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
#ifdef MEMPAGEHELPER_TRACKING
	validate_memory(memory, size);
#endif

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
#ifdef MEMPAGEHELPER_TRACKING
	validate_memory(memory, size);
#endif

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

uint32_t page_last_error(void)
{
	return last_error;
}

#define ERROR_BUFFER_SIZE (64 * 1024)

void page_error_free(void* message)
{
#ifdef MEMPAGEHELPER_TRACKING
	page_free(message, ERROR_BUFFER_SIZE);
#else
#if MEMPAGEHELPER_MSVC
	void* cache = InterlockedExchangePointer(&error_cache, message);
#else
	void* cache = __atomic_exchange_n(&error_cache, message, __ATOMIC_ACQ_REL);
#endif
	if (cache != NULL)
		free(cache);
#endif
}

MEMPAGEHELPER_ALLOCATOR(page_error_free, 1) MEMPAGEHELPER_INTERNAL(void*) page_error_alloc(void)
{
#ifdef MEMPAGEHELPER_TRACKING
	return page_alloc(ERROR_BUFFER_SIZE, PAGE_ACCESS_READ | PAGE_ACCESS_WRITE);
#else
#if MEMPAGEHELPER_MSVC
	void* cache = InterlockedExchangePointer(&error_cache, NULL);
#else
	void* cache = __atomic_exchange_n(&error_cache, NULL, __ATOMIC_ACQ_REL);
#endif
	return cache == NULL ? malloc(ERROR_BUFFER_SIZE) : cache;
#endif
}

MEMPAGEHELPER_SYSCHAR* page_error_message_sys(uint32_t error)
{
	MEMPAGEHELPER_SYSCHAR* buffer = page_error_alloc();
#if MEMPAGEHELPER_WINDOWS
	static_assert(ERROR_BUFFER_SIZE <= 64 * 1024);
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, buffer, ERROR_BUFFER_SIZE, NULL) == 0)
	{
		page_error_free(buffer);
		return NULL;
	}
#elif ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE) || defined(__APPLE__)
	int code = strerror_r((int)error, (char*)buffer, ERROR_BUFFER_SIZE);
	if (code != 0)
	{
		page_error_free(buffer);
		return NULL;
	}
#else
	unsigned char* message = (unsigned char*)strerror_r((int)error, (char*)buffer, ERROR_BUFFER_SIZE);
	if (message != buffer)
	{
		size_t len = strlen((char*)message);
		if (len > ERROR_BUFFER_SIZE - 2)
		{
			page_error_free(buffer);
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
	MEMPAGEHELPER_SYSCHAR* ptr = NULL;
	if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error, 0, (LPWSTR)&ptr, 1, NULL) == 0)
	{
		LocalFree(ptr);
		return NULL;
	}
	unsigned char* buffer = page_error_alloc();
	int out_len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, -1, (LPSTR)buffer, ERROR_BUFFER_SIZE, NULL, NULL);
	LocalFree(ptr);

	if (out_len <= 0)
		return NULL;

	return buffer;
#else
	return page_error_message_sys(error);
#endif
}

uint32_t page_lib_version(void)
{
	return MEMPAGEHELPER_VERSION;
}

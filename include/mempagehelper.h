#ifndef MEMPAGEHELPER_H
#define MEMPAGEHELPER_H

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER)
#define MEMPAGEHELPER_MSVC 1
#else
#define MEMPAGEHELPER_MSVC 0
#endif

#if !defined(__has_declspec_attribute)
#define __has_declspec_attribute(x) MEMPAGEHELPER_MSVC
#endif

#if !defined(__has_attribute)
#define __has_attribute(x) 0
#endif

#if defined(mempagehelper_EXPORTS)
#define MEMPAGEHELPER_DLL dllexport
#else
#error dupa
#define MEMPAGEHELPER_DLL dllimport
#endif

#if MEMPAGEHELPER_MSVC || defined(_WIN32) || defined(WIN32) || defined(CYGWIN)
#define MEMPAGEHELPER_WINDOWS 1
#else
#define MEMPAGEHELPER_WINDOWS 0
#endif

#if MEMPAGEHELPER_MSVC
#define MEMPAGEHELPER_PUBLIC_CCONV __cdecl
#else
#define MEMPAGEHELPER_PUBLIC_CCONV __attribute__ ((cdecl))
#endif

#if __has_declspec_attribute(MEMPAGEHELPER_DLL)
#define MEMPAGEHELPER_PUBLIC(ret) __declspec(MEMPAGEHELPER_DLL) ret MEMPAGEHELPER_PUBLIC_CCONV
#elif MEMPAGEHELPER_WINDOWS
#define MEMPAGEHELPER_PUBLIC(ret) __attribute__ ((MEMPAGEHELPER_DLL)) ret MEMPAGEHELPER_PUBLIC_CCONV
#else
#define MEMPAGEHELPER_PUBLIC(ret) __attribute__ ((visibility ("default"))) ret MEMPAGEHELPER_PUBLIC_CCONV
#endif

#if MEMPAGEHELPER_MSVC
#define MEMPAGEHELPER_INTERNAL_CCONV __vectorcall
#elif defined(__APPLE__)
#define MEMPAGEHELPER_INTERNAL_CCONV
#elif __has_attribute(vectorcall)
#define MEMPAGEHELPER_INTERNAL_CCONV __attribute__ ((vectorcall))
#elif __has_attribute(fastcall)
#define MEMPAGEHELPER_INTERNAL_CCONV __attribute__ ((fastcall))
#else
#define MEMPAGEHELPER_INTERNAL_CCONV
#endif

#if MEMPAGEHELPER_MSVC
#define MEMPAGEHELPER_INTERNAL(ret) ret MEMPAGEHELPER_INTERNAL_CCONV
#else
#define MEMPAGEHELPER_INTERNAL(ret) __attribute__ ((visibility ("hidden"))) ret MEMPAGEHELPER_INTERNAL_CCONV
#endif

#if MEMPAGEHELPER_MSVC
#define MEMPAGEHELPER_ALLOCATOR(free, index)
#elif defined(__APPLE__)
#define MEMPAGEHELPER_ALLOCATOR(free, index) __attribute__ ((malloc))
#else
#define MEMPAGEHELPER_ALLOCATOR(free, index) __attribute__ ((malloc, malloc (free, index)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MEMPAGEHELPER_VERSION (1 << 24 | 0 << 16 | 0 << 8 | 0)

#if MEMPAGEHELPER_WINDOWS
#define MEMPAGEHELPER_SYSCHAR wchar_t
#else
#define MEMPAGEHELPER_SYSCHAR unsigned char
#endif

	enum PAGE_ACCESS {
		PAGE_ACCESS_NONE = 0,
		PAGE_ACCESS_READ = 1,
		PAGE_ACCESS_WRITE = 2,
		PAGE_ACCESS_EXECUTE = 4
	};

	MEMPAGEHELPER_PUBLIC(uint32_t) page_size(void);
	MEMPAGEHELPER_PUBLIC(uint32_t) page_alloc_granularity(void);

	MEMPAGEHELPER_PUBLIC(int32_t) page_free(void* memory, size_t size);
	MEMPAGEHELPER_ALLOCATOR(page_free, 1) MEMPAGEHELPER_PUBLIC(void*) page_alloc(size_t size, PAGE_ACCESS access);
	MEMPAGEHELPER_PUBLIC(int32_t) page_change_access(void* memory, size_t size, PAGE_ACCESS access);

	MEMPAGEHELPER_PUBLIC(int32_t) page_lock(void* memory, size_t size);
	MEMPAGEHELPER_PUBLIC(int32_t) page_unlock(void* memory, size_t size);

	MEMPAGEHELPER_PUBLIC(int32_t) page_flush_instructions(void* memory, size_t size);

	MEMPAGEHELPER_PUBLIC(uint32_t) page_last_error(void);
	MEMPAGEHELPER_PUBLIC(void) page_error_free(void* message);
	MEMPAGEHELPER_ALLOCATOR(page_error_free, 1) MEMPAGEHELPER_PUBLIC(MEMPAGEHELPER_SYSCHAR*) page_error_message_sys(uint32_t error);
	MEMPAGEHELPER_ALLOCATOR(page_error_free, 1) MEMPAGEHELPER_PUBLIC(unsigned char*) page_error_message_utf8(uint32_t error);

	MEMPAGEHELPER_PUBLIC(uint32_t) page_lib_version(void);

#ifdef __cplusplus
}
#endif
#endif

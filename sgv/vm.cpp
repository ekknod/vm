#include "km.h"
#include "../shared/vm_windows.h"


//
// MMCOPYMEMORY is slower, but 100% crash free
// if you run to any issues uncomment it.
// 
// #define MMCOPYMEMORY


#include <TlHelp32.h>
#pragma comment(lib, "ntdll.lib")

#define POOLTAG (DWORD)'ECSG'
#define PAGE_SIZE  0x1000
#define PAGE_MASK  0xFFF
#define PAGE_SHIFT 12
#define SIZE_TO_PAGES(Size)  (((Size) >> PAGE_SHIFT) + (((Size) & PAGE_MASK) ? 1 : 0))
#define PAGES_TO_SIZE(Pages) ((Pages) << PAGE_SIZE)

std::vector<QWORD> km::global_export_list;
FILE_INFO          km::global_ntoskrnl;

NTOSKRNL_EXPORT(MmGetPhysicalMemoryRanges);
NTOSKRNL_EXPORT(ExAllocatePool2);
NTOSKRNL_EXPORT(ExFreePool);
NTOSKRNL_EXPORT(HalPrivateDispatchTable);
NTOSKRNL_EXPORT(PsLookupProcessByProcessId);
NTOSKRNL_EXPORT(PsGetProcessExitProcessCalled);
NTOSKRNL_EXPORT(PsGetProcessPeb);
NTOSKRNL_EXPORT(PsGetProcessWow64Process);
NTOSKRNL_EXPORT(MmCopyMemory);

namespace kernel
{
	NTOSKRNL_EXPORT(memcpy);
}

NTOSKRNL_EXPORT(PsGetCurrentProcess);
NTOSKRNL_EXPORT(PsGetCurrentProcessId);

namespace pm
{
#ifdef MMCOPYMEMORY
	static BOOL  read(QWORD address, PVOID buffer, QWORD length, QWORD* res);
#else
	static BOOL  read(QWORD address, PVOID buffer, QWORD length);
#endif
	static BOOL  write(QWORD address, PVOID buffer, QWORD length);
	static QWORD read_i64(QWORD address);
	static QWORD translate(QWORD dir, QWORD va);
}

QWORD g_memory_range_low;
QWORD g_memory_range_high;
QWORD KdMapPhysicalMemory64;
QWORD KdUnmapVirtualAddress;

typedef struct _PHYSICAL_MEMORY_RANGE
{
    union _LARGE_INTEGER BaseAddress;                                       //0x0
    union _LARGE_INTEGER NumberOfBytes;                                     //0x8
} PHYSICAL_MEMORY_RANGE;

typedef struct
{
	QWORD object;
	QWORD cr3;
} vm_handle_s;

namespace vm
{
	static BOOL init = 0;

	static QWORD allocate_memory(QWORD size)
	{
		return km::call(ExAllocatePool2, 0x0000000000000080UI64, PAGE_SIZE + size, POOLTAG);
	}

	static void free_memory(QWORD address)
	{
		km::call(ExFreePool, address, POOLTAG, 0, 0);
	}

	static BOOL initialize(void)
	{
		if (init)
			return 1;

		init = km::initialize();
		if (init)
		{
			QWORD memory_range_ptr = km::call(MmGetPhysicalMemoryRanges);

			int counter=0;
			while (1)
			{
				PHYSICAL_MEMORY_RANGE memory_range{};
				km::call(kernel::memcpy, (QWORD)&memory_range, memory_range_ptr + (counter * sizeof(PHYSICAL_MEMORY_RANGE)), sizeof(PHYSICAL_MEMORY_RANGE) );
				if (memory_range.BaseAddress.QuadPart == 0)
				{
					break;
				}
				counter++;
			}

			PHYSICAL_MEMORY_RANGE memory_range{};


			km::call(kernel::memcpy, (QWORD)&memory_range, memory_range_ptr + (0 * sizeof(PHYSICAL_MEMORY_RANGE)), sizeof(PHYSICAL_MEMORY_RANGE) );
			g_memory_range_low = memory_range.BaseAddress.QuadPart;

			km::call(kernel::memcpy, (QWORD)&memory_range, memory_range_ptr + ((counter-1) * sizeof(PHYSICAL_MEMORY_RANGE)), sizeof(PHYSICAL_MEMORY_RANGE) );
			g_memory_range_high = memory_range.BaseAddress.QuadPart + memory_range.NumberOfBytes.QuadPart;


			km::call(ExFreePool, memory_range_ptr);

			KdMapPhysicalMemory64 = (QWORD)HalPrivateDispatchTable;
			KdMapPhysicalMemory64 += 0x90;
			km::call(kernel::memcpy, (QWORD)&KdMapPhysicalMemory64, KdMapPhysicalMemory64, sizeof(KdMapPhysicalMemory64));

			KdUnmapVirtualAddress = (QWORD)HalPrivateDispatchTable;
			KdUnmapVirtualAddress += 0x98;
			km::call(kernel::memcpy, (QWORD)&KdUnmapVirtualAddress, KdUnmapVirtualAddress, sizeof(KdUnmapVirtualAddress));

			if (KdMapPhysicalMemory64 < km::global_ntoskrnl.base || KdMapPhysicalMemory64 > (km::global_ntoskrnl.base + km::global_ntoskrnl.size))
			{
				//
				// function is hooked, exit process
				//

				LOG("KdMapPhysicalMemory64 can't be used\n");

				ExitProcess(0);
				
				return 0;
			}

			if (KdUnmapVirtualAddress < km::global_ntoskrnl.base || KdUnmapVirtualAddress > (km::global_ntoskrnl.base + km::global_ntoskrnl.size))
			{
				//
				// function is hooked, exit process
				//

				LOG("KdUnmapVirtualAddress can't be used\n");

				ExitProcess(0);
				
				return 0;
			}
		}

		return init;
	}
}

VmOs vm::get_target_os(void)
{
	return VmOs::Windows;
}

BOOL vm::process_exists(PCSTR process_name)
{
	BOOL found = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		if (!strcmpi_imp(entry.szExeFile, process_name))
		{
			found = 1;
			break;
		}
	}

	CloseHandle(snapshot);

	return found;
}

vm_handle vm::open_process(PCSTR process_name)
{
	if (!initialize())
		return 0;

	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	while (Process32Next(snapshot, &entry))
	{
		if (!strcmpi_imp(entry.szExeFile, process_name))
		{
			if (km::call(PsLookupProcessByProcessId, (QWORD)entry.th32ProcessID, (QWORD)&process_handle) != 0)
			{
				process_handle = 0;
			}
			break;
		}
	}
	CloseHandle(snapshot);

	if (process_handle)
	{
		QWORD cr3=0;
		km::call(kernel::memcpy, (QWORD)&cr3, (QWORD)process_handle + 0x28, sizeof(cr3));

		vm_handle_s *s = (vm_handle_s*)malloc(sizeof(vm_handle_s));
		s->object = (QWORD)process_handle;
		s->cr3    = cr3;

		process_handle = (vm_handle)s;
	}

	return process_handle;
}

vm_handle vm::open_process_ex(PCSTR process_name, PCSTR dll_name)
{
	if (!initialize())
		return 0;

	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		if (!strcmpi_imp(entry.szExeFile, process_name))
		{
			if (km::call(PsLookupProcessByProcessId, (QWORD)entry.th32ProcessID, (QWORD)&process_handle) != 0)
			{
				process_handle = 0;
				continue;
			}


			QWORD cr3=0;
			km::call(kernel::memcpy, (QWORD)&cr3, (QWORD)process_handle + 0x28, sizeof(cr3));

			vm_handle_s *s = (vm_handle_s*)malloc(sizeof(vm_handle_s));
			s->object = (QWORD)process_handle;
			s->cr3    = cr3;

			process_handle = (vm_handle)s;


			if (get_module(process_handle, dll_name))
			{
				break;
			}

			vm::close((vm_handle)process_handle);
			process_handle = 0;
		}
	}

	CloseHandle(snapshot);

	return process_handle;
}

vm_handle vm::open_process_by_module_name(PCSTR dll_name)
{
	if (!initialize())
		return 0;

	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		if (km::call(PsLookupProcessByProcessId, (QWORD)entry.th32ProcessID, (QWORD)&process_handle) != 0)
		{
			process_handle = 0;
			continue;
		}

		QWORD cr3=0;
		km::call(kernel::memcpy, (QWORD)&cr3, (QWORD)process_handle + 0x28, sizeof(cr3));

		vm_handle_s *s = (vm_handle_s*)malloc(sizeof(vm_handle_s));
		s->object = (QWORD)process_handle;
		s->cr3    = cr3;

		process_handle = (vm_handle)s;


		if (get_module(process_handle, dll_name))
		{
			break;
		}

		vm::close((vm_handle)process_handle);
		process_handle = 0;
	}

	CloseHandle(snapshot);

	return process_handle;
}

void vm::close(vm_handle process)
{
	if (process)
	{
		free(process);
	}
}

BOOL vm::running(vm_handle process)
{
	if (!initialize())
		return 0;

	if (process == 0)
		return 0;

	vm_handle_s *s = (vm_handle_s*)process;

	QWORD exit_called = km::call(PsGetProcessExitProcessCalled, (QWORD)s->object);
	return ((BOOLEAN*)&exit_called)[0] == 0;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (!initialize())
		return 0;

	if (process == 0)
		return 0;

	vm_handle_s *s = (vm_handle_s*)process;

	QWORD total_size = length;
	QWORD offset = 0;
	QWORD bytes_read=0;
	QWORD physical_address;
	QWORD current_size;
	int   cnt=0;

	while (total_size)
	{
		physical_address = pm::translate(s->cr3, address + offset);
		if (!physical_address)
		{
			if (total_size >= 0x1000)
			{
				bytes_read = 0x1000;
			}
			else
			{
				bytes_read = total_size;
			}
			memset((PVOID)((QWORD)buffer + offset), 0, bytes_read);
			goto E0;
		}

		current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
#ifdef MMCOPYMEMORY
		if (!pm::read(physical_address, (PVOID)((QWORD)buffer + offset), current_size, &bytes_read))
		{
			break;
		}
#else
		if (!pm::read(physical_address, (PVOID)((QWORD)buffer + offset), current_size))
		{
			break;
		}
		bytes_read = current_size;
#endif
		cnt++;
	E0:
		total_size -= bytes_read;
		offset += bytes_read;
	}
	return cnt != 0;
}

BOOL vm::write(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (!initialize())
		return 0;

	if (process == 0)
		return 0;

	vm_handle_s *s = (vm_handle_s*)process;

	QWORD total_size = length;
	QWORD offset = 0;
	QWORD bytes_write=0;

	QWORD physical_address;
	QWORD current_size;
	int   cnt=0;

	while (total_size) {
		physical_address = pm::translate(s->cr3, address + offset);
		if (!physical_address) {
			if (total_size >= 0x1000)
			{
				bytes_write = 0x1000;
			}
			else
			{
				bytes_write = total_size;
			}
			goto E0;
		}
		current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
		if (!pm::write(physical_address, (PVOID)((QWORD)buffer + offset), current_size))
		{
			break;
		}
		cnt++;
		bytes_write = current_size;
	E0:
		total_size -= bytes_write;
		offset += bytes_write;
	}
	return cnt != 0;
}

QWORD vm::get_peb(vm_handle process)
{
	if (!initialize())
		return 0;

	if (process == 0)
		return 0;

	vm_handle_s *s = (vm_handle_s*)process;

	return (QWORD)km::call(PsGetProcessPeb, (QWORD)s->object);
}

QWORD vm::get_wow64_process(vm_handle process)
{
	if (!initialize())
		return 0;

	if (process == 0)
		return 0;

	vm_handle_s *s = (vm_handle_s*)process;

	return (QWORD)km::call(PsGetProcessWow64Process, (QWORD)s->object);
}

QWORD vm::get_module(vm_handle process, PCSTR dll_name)
{
	return vmwin::get_module(process, dll_name);
}

QWORD vm::get_module_export(vm_handle process, QWORD base, PCSTR export_name)
{
	return vmwin::get_module_export(process, base, export_name);
}


PVOID vm::dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
{
	return vmwin::dump_module(process, base, module_type);
}

void vm::free_module(PVOID dumped_module)
{
	return vmwin::free_module(dumped_module);
}

QWORD vm::get_dump_export(PVOID dumped_module, PCSTR export_name)
{
	return vmwin::get_dump_export(dumped_module, export_name);
}

QWORD vm::scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
{
	return vmwin::scan_pattern(dumped_module, pattern, mask, length);
}

QWORD vm::scan_pattern_direct(vm_handle process, QWORD base, PCSTR pattern, PCSTR mask, DWORD length)
{
	return vmwin::scan_pattern_direct(process, base, pattern, mask, length);
}

#ifdef MMCOPYMEMORY
static BOOL pm::read(QWORD address, PVOID buffer, QWORD length, QWORD* res)
{
	if (address < (QWORD)g_memory_range_low)
	{
		return 0;
	}

	if (address + length > g_memory_range_high)
	{
		return 0;
	}

	if (length > 0x1000)
	{
		length = 0x1000;
	}

	QWORD alloc_buffer = (QWORD)vm::allocate_memory(length);
	if (alloc_buffer == 0)
	{
		return 0;
	}
	
	QWORD bytes_read = 0;
	QWORD status = km::call(MmCopyMemory, (QWORD)alloc_buffer, address, length, 0x01, (QWORD)&bytes_read);
	if (status == 0)
	{
		km::call(kernel::memcpy, (QWORD)buffer, alloc_buffer, bytes_read);
		if (res)
		{
			*res = bytes_read;
		}
	}
	vm::free_memory(alloc_buffer);
	return status == 0;
}
#else
static BOOL pm::read(QWORD address, PVOID buffer, QWORD length)
{
	if (address < (QWORD)g_memory_range_low)
	{
		return 0;
	}

	if (address + length > g_memory_range_high)
	{
		return 0;
	}


	BOOL status      = 0;
	ULONG page_count = (ULONG)SIZE_TO_PAGES(length);
	QWORD va         = km::call(KdMapPhysicalMemory64, address, page_count, 1);	
	if (va)
	{
		km::call(kernel::memcpy, (QWORD)buffer, va, length);
		km::call(KdUnmapVirtualAddress, va, page_count, 0);
		status = 1;
	}
	return status;
}
#endif

static BOOL pm::write(QWORD address, PVOID buffer, QWORD length)
{
	if (address < (QWORD)g_memory_range_low)
	{
		return 0;
	}

	if (address + length > g_memory_range_high)
	{
		return 0;
	}

	BOOL status      = 0;
	ULONG page_count = (ULONG)SIZE_TO_PAGES(length);
	QWORD va         = km::call(KdMapPhysicalMemory64, address, page_count, 1);
	
	if (va)
	{
		km::call(kernel::memcpy, va, (QWORD)buffer, length);

		km::call(KdUnmapVirtualAddress, va, page_count, 0);

		status = 1;
	}

	return status;
}

static QWORD pm::read_i64(QWORD address)
{
	QWORD result = 0;
#ifdef MMCOPYMEMORY
	if (!read(address, &result, sizeof(result), 0))
#else
	if (!read(address, &result, sizeof(result)))
#endif
	{
		return 0;
	}
	return result;
}

static QWORD pm::translate(QWORD dir, QWORD va)
{
	__int64 v2; // rax
	__int64 v3; // rax
	__int64 v5; // rax
	__int64 v6; // rax

	v2 = pm::read_i64(8 * ((va >> 39) & 0x1FF) + dir);
	if ( !v2 )
		return 0i64;

	if ( (v2 & 1) == 0 )
		return 0i64;

	v3 = pm::read_i64((v2 & 0xFFFFFFFFF000i64) + 8 * ((va >> 30) & 0x1FF));
	if ( !v3 || (v3 & 1) == 0 )
		return 0i64;

	if ( (v3 & 0x80u) != 0i64 )
		return (va & 0x3FFFFFFF) + (v3 & 0xFFFFFFFFF000i64);

	v5 = pm::read_i64((v3 & 0xFFFFFFFFF000i64) + 8 * ((va >> 21) & 0x1FF));
	if ( !v5 || (v5 & 1) == 0 )
		return 0i64;

	if ( (v5 & 0x80u) != 0i64 )
		return (va & 0x1FFFFF) + (v5 & 0xFFFFFFFFF000i64);

	v6 = pm::read_i64((v5 & 0xFFFFFFFFF000i64) + 8 * ((va >> 12) & 0x1FF));
	if ( v6 && (v6 & 1) != 0 )
		return (va & 0xFFF) + (v6 & 0xFFFFFFFFF000i64);

	return 0i64;
}


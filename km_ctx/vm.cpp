#include "../shared/vm_windows.h"
#include <intrin.h>
#include <ntifs.h>

extern "C" __declspec(dllimport) PCSTR PsGetProcessImageFileName(PEPROCESS);
extern "C" __declspec(dllimport) BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS);
extern "C" __declspec(dllimport) PVOID PsGetProcessPeb(PEPROCESS);
extern "C" __declspec(dllimport) PVOID PsGetProcessWow64Process(PEPROCESS);

namespace km
{
	extern BOOL memcpy_impl(void *dest, const void *src, QWORD size);
}

static vm_handle get_process_by_name(PCSTR process_name)
{
	QWORD process;
	QWORD entry;

	DWORD gActiveProcessLink = *(DWORD*)((BYTE*)PsGetProcessId + 3) + 8;
	process = (QWORD)PsInitialSystemProcess;

	entry = process;
	do {
		if (PsGetProcessExitProcessCalled((PEPROCESS)entry))
			goto L0;

		if (PsGetProcessImageFileName((PEPROCESS)entry) &&
			strcmpi_imp(PsGetProcessImageFileName((PEPROCESS)entry), process_name) == 0) {
			return (vm_handle)entry;
		}
	L0:
		entry = *(QWORD*)(entry + gActiveProcessLink) - gActiveProcessLink;
	} while (entry != process);

	return 0;
}

VmOs vm::get_target_os(void)
{
	return VmOs::Windows;
}

BOOL vm::process_exists(PCSTR process_name)
{
	return get_process_by_name(process_name) != 0;
}

vm_handle vm::open_process(PCSTR process_name)
{
	UNREFERENCED_PARAMETER(process_name);
	return *(vm_handle*)(__readgsqword(0x188) + 0xB8);
}

vm_handle vm::open_process_ex(PCSTR process_name, PCSTR dll_name)
{
	UNREFERENCED_PARAMETER(process_name);
	UNREFERENCED_PARAMETER(dll_name);
	return *(vm_handle*)(__readgsqword(0x188) + 0xB8);
}

vm_handle vm::open_process_by_module_name(PCSTR dll_name)
{
	UNREFERENCED_PARAMETER(dll_name);
	return *(vm_handle*)(__readgsqword(0x188) + 0xB8);
}

void vm::close(vm_handle process)
{
	UNREFERENCED_PARAMETER(process);
}

BOOL vm::running(vm_handle process)
{
	if (process == 0)
		return 0;
	return PsGetProcessExitProcessCalled((PEPROCESS)process) == 0;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (!running(process))
	{
		return 0;
	}
	if ((address + length) > (ULONG_PTR)0x7FFFFFFEFFFF)
	{
		return 0;
	}
	if (address < (QWORD)0x10000)
	{
		return 0;
	}
	QWORD physical_address = (QWORD)PAGE_ALIGN(MmGetPhysicalAddress((PVOID)address).QuadPart);
	if (physical_address == 0)
	{
		return 0;
	}
	if (!MmIsAddressValid((PVOID)address))
	{
		return 0;
	}
	return km::memcpy_impl(buffer, (PVOID)address, length);
}

BOOL vm::write(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (!running(process))
	{
		return 0;
	}
	if ((address + length) > (ULONG_PTR)0x7FFFFFFEFFFF)
	{
		return 0;
	}
	if (address < (QWORD)0x10000)
	{
		return 0;
	}
	QWORD physical_address = (QWORD)PAGE_ALIGN(MmGetPhysicalAddress((PVOID)address).QuadPart);
	if (physical_address == 0)
	{
		return 0;
	}
	if (!MmIsAddressValid((PVOID)address))
	{
		return 0;
	}
	return km::memcpy_impl((void *)address, buffer, length);
}

QWORD vm::get_peb(vm_handle process)
{
	if (process == 0)
		return 0;
	return (QWORD)PsGetProcessPeb((PEPROCESS)process);
}

QWORD vm::get_wow64_process(vm_handle process)
{
	if (process == 0)
		return 0;
	return (QWORD)PsGetProcessWow64Process((PEPROCESS)process);
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


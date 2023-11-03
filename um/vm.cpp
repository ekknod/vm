//
// vmwin
//
#include "../shared/vm_windows.h"

#include <TlHelp32.h>
#pragma comment(lib, "ntdll.lib")

extern "C" __kernel_entry NTSTATUS NtQueryInformationProcess(
	HANDLE           ProcessHandle,
	ULONG            ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

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
	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		if (!strcmpi_imp(entry.szExeFile, process_name))
		{
			process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
			break;
		}
	}

	CloseHandle(snapshot);

	return process_handle;
}

vm_handle vm::open_process_ex(PCSTR process_name, PCSTR dll_name)
{
	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		if (!strcmpi_imp(entry.szExeFile, process_name))
		{
			process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);

			if (!process_handle)
			{
				continue;
			}

			if (get_module(process_handle, dll_name))
			{
				break;
			}

			CloseHandle(process_handle);
			process_handle = 0;
		}
	}

	CloseHandle(snapshot);

	return process_handle;
}

vm_handle vm::open_process_by_module_name(PCSTR dll_name)
{
	vm_handle process_handle = 0;

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(snapshot, &entry))
	{
		process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);

		if (!process_handle)
		{
			continue;
		}

		if (get_module(process_handle, dll_name))
		{
			break;
		}

		CloseHandle(process_handle);
		process_handle = 0;
	}

	CloseHandle(snapshot);

	return process_handle;
}

void vm::close(vm_handle process)
{
	if (process)
	{
		CloseHandle(process);
	}
}

BOOL vm::running(vm_handle process)
{
	if (!process)
		return 0;

	DWORD ret = 0;
	GetExitCodeProcess(process, &ret);

	return ret == STATUS_PENDING;
}

BOOL vm::read(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (process == 0)
		return 0;

	SIZE_T ret = 0;
	if (!ReadProcessMemory(process, (LPCVOID)address, buffer, length, &ret))
	{
		return 0;
	}
	return ret == length;
}

BOOL vm::write(vm_handle process, QWORD address, PVOID buffer, QWORD length)
{
	if (process == 0)
		return 0;

	SIZE_T ret = 0;
	if (!WriteProcessMemory(process, (LPVOID)address, buffer, length, &ret))
	{
		return 0;
	}
	return ret == length;
}

QWORD vm::get_peb(vm_handle process)
{
	QWORD peb[6]{};

	if (NtQueryInformationProcess(process, 0, &peb, 48, 0) != 0)
	{
		return 0;
	}

	return peb[1];
}

QWORD vm::get_wow64_process(vm_handle process)
{
	QWORD wow64_process = 0;

	if (process == 0)
		return wow64_process;

	if (NtQueryInformationProcess(process, 26, &wow64_process, 8, 0) != 0)
	{
		return 0;
	}

	return wow64_process;
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


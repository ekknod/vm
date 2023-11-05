#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string>
#include <vector>
#pragma comment(lib, "ntdll.lib")

typedef ULONG_PTR QWORD;

#define LOG(...) printf("[Client.exe] "  __VA_ARGS__)
#define NTOSKRNL_EXPORT(EXPORT_NAME) km::DLL_EXPORT EXPORT_NAME((QWORD)#EXPORT_NAME)

#pragma pack(1)
typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;

#pragma pack(push, 8)
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

std::vector<FILE_INFO> get_kernel_modules(void)
{
	std::vector<FILE_INFO> driver_information;


	ULONG req = 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &req);
	if (status != 0xC0000004)
	{
		return driver_information;
	}

	PRTL_PROCESS_MODULES system_modules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, req, MEM_COMMIT, PAGE_READWRITE);

	status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, system_modules, req, &req);

	if (status != 0)
	{
		VirtualFree(system_modules, 0, MEM_RELEASE);
		return driver_information;
	}

	for (ULONG i = system_modules->NumberOfModules; i--;)
	{
		RTL_PROCESS_MODULE_INFORMATION entry = system_modules->Modules[i];	
		char *sub_string = strstr((char *const)entry.FullPathName, "system32");
		if (sub_string == 0)
		{
			sub_string = strstr((char *const)entry.FullPathName, "System32");
		}

		std::string path;
		if (sub_string)
		{
			path = "C:\\Windows\\" + std::string(sub_string);
		}
		else
		{
			path = std::string((const char *)entry.FullPathName);
		}

		PCSTR name = (PCSTR)&entry.FullPathName[entry.OffsetToFileName];

		FILE_INFO temp_information;
		temp_information.path = path;
		temp_information.name = name;
		temp_information.base = (QWORD)entry.ImageBase;
		temp_information.size = (QWORD)entry.ImageSize;
		driver_information.push_back(temp_information);	
	}
	
	VirtualFree(system_modules, 0, MEM_RELEASE);

	return driver_information;
}

QWORD get_kernel_export(QWORD base, PCSTR driver_name, PCSTR export_name)
{
	HMODULE ntos = LoadLibraryA(driver_name);

	if (ntos == 0)
	{
		return 0;
	}

	QWORD export_address = (QWORD)GetProcAddress(ntos, export_name);
	if (export_address == 0)
	{
		goto cleanup;
	}

	export_address = export_address - (QWORD)ntos;
	export_address = export_address + base;

cleanup:
	FreeLibrary(ntos);
	return export_address;
}

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
extern "C" NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);

namespace km
{
	extern std::vector<QWORD> global_export_list;
	extern FILE_INFO          global_ntoskrnl;

	class DLL_EXPORT
	{
		QWORD address;
	public:
		DLL_EXPORT(QWORD address) : address(address)
		{
			global_export_list.push_back((QWORD)&this->address);
		}
		operator QWORD () const { return address; }
	};

	QWORD call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		#pragma pack(push,1)
		typedef struct {
			QWORD param_1;
			QWORD param_2;
			QWORD param_3;
			QWORD param_4;
			QWORD param_5;
			QWORD param_6;
			QWORD param_7;
		} PAYLOAD ;
		#pragma pack(pop)

		PAYLOAD parameters;
		parameters.param_1 = r1;
		parameters.param_2 = r2;
		parameters.param_3 = r3;
		parameters.param_4 = r4;
		parameters.param_5 = r5;
		parameters.param_6 = r6;
		parameters.param_7 = r7;

		QWORD peb = __readgsqword(0x60);
		peb = *(QWORD*)(peb + 0x18);
		peb = *(QWORD*)(peb + 0x20);

		*(QWORD*)(peb + 0x18) = kernel_address;
		*(QWORD*)(peb + 0x10) = (QWORD)&parameters;

		UNICODE_STRING string;
		RtlInitUnicodeString(&string, L"SecureBoot");

		ULONG ret = 0;
		ULONG ret_len = 1;
		ULONG attributes = 0;

		GUID gEfiGlobalVariableGuid         = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }};
		NTSTATUS status = NtQuerySystemEnvironmentValueEx(&string,
							&gEfiGlobalVariableGuid,
							&ret,
							&ret_len,
							&attributes);

		QWORD rax = *(QWORD*)(peb + 0x18);
		*(QWORD*)(peb + 0x18) = 0;
		*(QWORD*)(peb + 0x10) = 0;

		if (NT_SUCCESS(status))
			return 0;

		return rax;
	}

	template <typename T>
	T call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		QWORD ret = call(kernel_address, r1, r2, r3, r4, r5, r6, r7);
		return *(T*)&ret;
	}

	BOOL initialize(void)
	{

		for (auto &drv : get_kernel_modules())
		{
			if (!_strcmpi(drv.name.c_str(), "ntoskrnl.exe"))
			{
				global_ntoskrnl = drv;
				break;
			}
		}

		if (global_ntoskrnl.base == 0)
		{
			LOG("ntoskrnl.exe base address not found\n");
			return 0;
		}

		for (auto &i : global_export_list)
		{
			QWORD temp = *(QWORD*)i;

			*(QWORD*)i = get_kernel_export(global_ntoskrnl.base, "ntoskrnl.exe", (PCSTR)temp);
			if (*(QWORD*)i == 0)
			{
				LOG("export %s not found\n", (PCSTR)temp);
				return 0;
			}
		}

		BOOLEAN privs=1;
		if (RtlAdjustPrivilege(22, 1, 0, &privs) != 0l)
		{
			LOG("run as admin\n");
			return 0;
		}
		return 1;
	}
}


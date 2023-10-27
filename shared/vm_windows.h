#ifndef VM_WINDOWS_H
#define VM_WINDOWS_H

#include "../vm.h"

//
// wmwin is private header used by vm.cpp only
//
namespace vmwin
{
	inline QWORD get_module(vm_handle process, PCSTR dll_name)
	{
		QWORD peb = vm::get_wow64_process(process);

		DWORD a0[6]{};
		QWORD a1, a2;
		unsigned short a3[120]{};

		QWORD(*read_ptr)(vm_handle process, QWORD address) = 0;
		if (peb)
		{
			*(QWORD*)&read_ptr = (QWORD)vm::read_i32;
			a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10, a0[5] = 0x20;
		}
		else
		{
			*(QWORD*)&read_ptr = (QWORD)vm::read_i64;
			peb = vm::get_peb(process);
			a0[0] = 0x08, a0[1] = 0x18, a0[2] = 0x20, a0[3] = 0x50, a0[4] = 0x20, a0[5] = 0x40;
		}

		if (peb == 0)
		{
			return 0;
		}

		a1 = read_ptr(process, peb + a0[1]);
		if (a1 == 0)
		{
			return 0;
		}

		a1 = read_ptr(process, a1 + a0[2]);
		if (a1 == 0)
		{
			return 0;
		}

		a2 = read_ptr(process, a1 + a0[0]);

		int name_length = (int)strlen_imp(dll_name);
		if (name_length > 120)
			name_length = 120;

		while (a1 != a2) {
			if (dll_name == 0)
				return read_ptr(process, a1 + a0[4]);

			QWORD a4 = read_ptr(process, a1 + a0[3]);					
			vm::read(process, a4, a3, (name_length*2)+2);

			char final_name[120]{};
			for (int i = 0; i < 120; i++) {
				final_name[i] = (char)a3[i];
				if (a3[i] == 0)
					break;
			}

			if (strcmpi_imp((PCSTR)final_name, dll_name) == 0)
			{
				return read_ptr(process, a1 + a0[4]);
			}
			
			a1 = read_ptr(process, a1);
			if (a1 == 0)
				break;
		}
		return 0;
	}

	QWORD get_module_export(vm_handle process, QWORD base, PCSTR export_name)
	{
		QWORD a0;
		DWORD a1[4]{};
		char a2[260]{};

		a0 = base + vm::read_i16(process, base + 0x3C);
		if (a0 == base)
		{
			return 0;
		}

		WORD  machine = vm::read_i16(process, a0 + 0x4);
		DWORD wow64_offset = machine == 0x8664 ? 0x88 : 0x78;

		a0 = base + (QWORD)vm::read_i32(process, a0 + wow64_offset);
		if (a0 == base)
		{
			return 0;
		}

		int name_length = (int)strlen_imp(export_name);
		if (name_length > 120)
			name_length = 120;

		vm::read(process, a0 + 0x18, &a1, sizeof(a1));
		while (a1[0]--)
		{
			a0 = (QWORD)vm::read_i32(process, base + a1[2] + ((QWORD)a1[0] * 4));
			if (a0)
			{
				vm::read(process, base + a0, &a2, name_length);
				a2[name_length] = 0;

				if (!strcmpi_imp(a2, export_name))
				{
					DWORD tmp = vm::read_i16(process, base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
					DWORD tmp2 = vm::read_i32(process, base + a1[1] + tmp);
					return (base + tmp2);
				}
			}
		}
		return 0;
	}

	inline PVOID dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
	{
		QWORD nt_header;
		DWORD image_size;
		BYTE* ret;

		if (base == 0)
		{
			return 0;
		}

		nt_header = (QWORD)vm::read_i32(process, base + 0x03C) + base;
		if (nt_header == base)
		{
			return 0;
		}

		image_size = vm::read_i32(process, nt_header + 0x050);
		if (image_size == 0)
		{
			return 0;
		}

	#ifdef _KERNEL_MODE
		ret = (BYTE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (QWORD)(image_size + 16), 'ofnI');
	#else
		ret = (BYTE*)malloc((QWORD)image_size + 16);
	#endif
		if (ret == 0)
			return 0;

		*(QWORD*)(ret + 0) = base;
		*(QWORD*)(ret + 8) = image_size;
		ret += 16;

		DWORD headers_size = vm::read_i32(process, nt_header + 0x54);
		vm::read(process, base, ret, headers_size);

		WORD machine = vm::read_i16(process, nt_header + 0x4);
		QWORD section_header = machine == 0x8664 ?
			nt_header + 0x0108 :
			nt_header + 0x00F8;


		for (WORD i = 0; i < vm::read_i16(process, nt_header + 0x06); i++) {
			QWORD section = section_header + ((QWORD)i * 40);
			if (module_type == VM_MODULE_TYPE::CodeSectionsOnly)
			{
				DWORD section_characteristics = vm::read_i32(process, section + 0x24);
				if (!(section_characteristics & 0x00000020))
					continue;
			}

			QWORD target_address = (QWORD)ret + (QWORD)vm::read_i32(process, section + ((module_type == VM_MODULE_TYPE::Raw) ? 0x14 : 0x0C));
			QWORD virtual_address = base + (QWORD)vm::read_i32(process, section + 0x0C);
			DWORD virtual_size = vm::read_i32(process, section + 0x08);
			vm::read(process, virtual_address, (PVOID)target_address, virtual_size);
		}

		return (PVOID)ret;
	}

	inline void free_module(PVOID dumped_module)
	{
		QWORD a0 = (QWORD)dumped_module;

		a0 -= 16;
	#ifdef _KERNEL_MODE
		ExFreePoolWithTag((void*)a0, 'ofnI');
	#else
		free((void*)a0);
	#endif
	}

	namespace utils
	{
		inline BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
		{

			for (; *szMask; ++szMask, ++pData, ++bMask)
				if (*szMask == 'x' && *pData != *bMask)
					return 0;

			return (*szMask) == 0;
		}

		inline QWORD FindPatternEx(QWORD dwAddress, QWORD dwLen, BYTE* bMask, char* szMask)
		{

			if (dwLen <= 0)
				return 0;
			for (QWORD i = 0; i < dwLen; i++)
				if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
					return (QWORD)(dwAddress + i);

			return 0;
		}
	}

	inline QWORD scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
	{
		QWORD ret = 0;

		if (dumped_module == 0)
			return 0;

		QWORD dos_header = (QWORD)dumped_module;
		QWORD nt_header = (QWORD) * (DWORD*)(dos_header + 0x03C) + dos_header;
		WORD  machine = *(WORD*)(nt_header + 0x4);

		QWORD section_header = machine == 0x8664 ?
			nt_header + 0x0108 :
			nt_header + 0x00F8;

		for (WORD i = 0; i < *(WORD*)(nt_header + 0x06); i++) {

			QWORD section = section_header + ((QWORD)i * 40);
			DWORD section_characteristics = *(DWORD*)(section + 0x24);

			if (section_characteristics & 0x00000020)
			{
				QWORD section_address = dos_header + (QWORD) * (DWORD*)(section + 0x0C);
				DWORD section_size = *(DWORD*)(section + 0x08);
				QWORD address = utils::FindPatternEx(section_address, section_size - length, (BYTE*)pattern, (char*)mask);
				if (address)
				{
					ret = (address - (QWORD)dumped_module) +
						*(QWORD*)((QWORD)dumped_module - 16);
					break;
				}
			}

		}
		return ret;
	}

	QWORD scan_pattern_direct(vm_handle process, QWORD base, PCSTR pattern, PCSTR mask, DWORD length)
	{
		if (base == 0)
		{
			return 0;
		}
	
		PVOID dumped_module = dump_module(process, base, VM_MODULE_TYPE::CodeSectionsOnly);
		if (dumped_module == 0)
		{
			return 0;
		}

		QWORD patt = scan_pattern(dumped_module, pattern, mask, length);

		free_module(dumped_module);
		return patt;
	}
}



#endif


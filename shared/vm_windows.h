#ifndef VM_WINDOWS_H
#define VM_WINDOWS_H

#include "../vm.h"

//
// wmwin is private header used by vm.cpp only
//
namespace vmwin
{
	inline QWORD read_i32w(vm_handle process, QWORD address) { return (QWORD)vm::read_i32(process, address); }
	inline QWORD get_module(vm_handle process, PCSTR dll_name)
	{
		QWORD peb = vm::get_wow64_process(process);

		DWORD a0[6]{};
		QWORD a1, a2, a4;
		unsigned char a3[240]{};

		QWORD(*read_ptr)(vm_handle process, QWORD address) = 0;
		if (peb)
		{
			read_ptr = read_i32w;
			a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10, a0[5] = 0x20;
		}
		else
		{
			read_ptr = vm::read_i64;
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


		//
		// return first list entry, if parameter is null
		//
		if (dll_name == 0)
			return read_ptr(process, a1 + a0[4]);


		int name_length = (int)strlen_imp(dll_name);
		if (name_length > 119)
			name_length = 119;


		a2 = read_ptr(process, a1 + a0[0]);
		while (a1 != a2)
		{
			a4 = read_ptr(process, a1 + a0[3]);

			//
			// if no module name, we skip the module
			//
			if (a4 == 0)
			{
				goto next_entry;
			}

			vm::read(process, a4, a3, (name_length*2)+2);
			wcs2str((short*)a3, name_length+1);
			a3[name_length+1] = 0;

			if (strcmpi_imp((PCSTR)a3, dll_name) == 0)
			{
				return read_ptr(process, a1 + a0[4]);
			}
		next_entry:
			a1 = read_ptr(process, a1);
			if (a1 == 0)
			{
				break;
			}
		}
		return 0;
	}

	QWORD get_module_export(vm_handle process, QWORD base, PCSTR export_name)
	{
		QWORD a0;
		DWORD a1[4]{};
		char  a2[120]{};

		a0 = base + vm::read_i16(process, base + 0x3C);
		if (a0 == base)
		{
			return 0;
		}

		DWORD wow64_off = vm::read_i16(process, a0 + 0x4) == 0x8664 ? 0x88 : 0x78;

		a0 = base + (QWORD)vm::read_i32(process, a0 + wow64_off);
		if (a0 == base)
		{
			return 0;
		}

		int name_length = (int)strlen_imp(export_name);
		if (name_length > 119)
			name_length = 119;

		vm::read(process, a0 + 0x18, &a1, sizeof(a1));
		while (a1[0]--)
		{
			a0 = (QWORD)vm::read_i32(process, base + a1[2] + ((QWORD)a1[0] * 4));
			if (a0 == 0)
			{
				continue;
			}

			vm::read(process, base + a0, &a2, name_length + 1);
			a2[name_length + 1] = 0;

			if (!strcmpi_imp(a2, export_name))
			{
				a0 = vm::read_i16(process, base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
				a0 = vm::read_i32(process, base + a1[1] + a0);
				return (base + a0);
			}
		}
		return 0;
	}

	inline PVOID dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
	{
		if (base == 0)
		{
			return 0;
		}

		QWORD nt_header = (QWORD)vm::read_i32(process, base + 0x03C) + base;
		if (nt_header == base)
		{
			return 0;
		}

		DWORD image_size = vm::read_i32(process, nt_header + 0x050);
		if (image_size == 0)
		{
			return 0;
		}

	#ifdef _KERNEL_MODE
		BYTE *ret = (BYTE*)ExAllocatePoolWithTag(NonPagedPoolNx, (QWORD)(image_size + 16), 'ofnI');
	#else
		BYTE *ret = (BYTE*)malloc((QWORD)image_size + 16);
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

			else if (module_type == VM_MODULE_TYPE::ReadOnly)
			{
				DWORD section_characteristics = vm::read_i32(process, section + 0x24);
				if (!(section_characteristics & 0x40000000)) // IMAGE_SCN_MEM_READ
				{
					continue;
				}
				if ((section_characteristics & 0x80000000)) // IMAGE_SCN_MEM_WRITE
				{
					continue;
				}
				if ((section_characteristics & 0x20000000)) // IMAGE_SCN_MEM_EXECUTE
				{
					continue;
				}
				if ((section_characteristics & 0x02000000)) // IMAGE_SCN_MEM_DISCARDABLE
				{
					continue;
				}
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

	inline QWORD get_dump_export(PVOID dumped_module, PCSTR export_name)
	{
		QWORD a0;
		DWORD a1[4]{};


		QWORD base = (QWORD)dumped_module;


		a0 = base + *(WORD*)(base + 0x3C);
		if (a0 == base)
		{
			return 0;
		}

		DWORD wow64_off = *(WORD*)(a0 + 0x4) == 0x8664 ? 0x88 : 0x78;

		a0 = base + (QWORD)*(DWORD*)(a0 + wow64_off);
		if (a0 == base)
		{
			return 0;
		}

		memcpy(&a1, (const void *)(a0 + 0x18), sizeof(a1));
		while (a1[0]--)
		{
			a0 = (QWORD)*(DWORD*)(base + a1[2] + ((QWORD)a1[0] * 4));
			if (a0 == 0)
			{
				continue;
			}

			if (!strcmpi_imp((const char*)(base + a0), export_name))
			{
				a0 = *(WORD*)(base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
				a0 = *(DWORD*)(base + a1[1] + a0);
				return (*(QWORD*)((QWORD)dumped_module - 16) + a0);
			}
		}
		return 0;
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


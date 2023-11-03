#ifndef VM_LINUX_H
#define VM_LINUX_H

#include "../vm.h"
#include <elf.h>
#include <byteswap.h>

//
// wmwin is private header used by vm.cpp only
//
namespace vmlinux
{
	inline QWORD get_elf_address(vm_handle process, QWORD base, int tag)
	{
		BOOL wow64 = (vm::read_i16(process, base + 0x12) == 62) ? 0 : 1;
	
		int pht_count;
		int pht_file_offset;
		int pht_size;

		if (wow64)
		{
			pht_count = 0x2C, pht_file_offset = 0x1C, pht_size = 32;
		}
		else
		{
			pht_count = 0x38, pht_file_offset = 0x20, pht_size = 56;
		}

		QWORD a0 = vm::read_i32(process, base + pht_file_offset) + base;

		for (WORD i = 0; i < vm::read_i16(process, base + pht_count); i++)
		{
			QWORD a2 = pht_size * i + a0;
			if (vm::read_i32(process, a2) == tag)
			{
				return a2;
			}
		}
		return 0;
	}

	inline QWORD get_dyn_address(vm_handle process, QWORD base, QWORD tag)
	{
		QWORD dyn = get_elf_address(process, base, 2);
		if (dyn == 0)
		{
			return 0;
		}

		BOOL wow64 = (vm::read_i16(process, base + 0x12) == 62) ? 0 : 1;

		int reg_size = wow64 ? 4 : 8;
	
		vm::read(process, dyn + (2*reg_size), &dyn, reg_size);

		dyn += base;
	
		while (1)
		{
			QWORD dyn_tag = 0;
			vm::read(process, dyn, &dyn_tag, reg_size);

			if (dyn_tag == 0)
			{
				break;
			}

			if (dyn_tag == tag)
			{
				QWORD address = 0;
				vm::read(process, dyn + reg_size, &address, reg_size);
				return address;
			}

			dyn += (2*reg_size);
		}
		return 0;
	}

	QWORD get_module_export(vm_handle process, QWORD base, PCSTR export_name)
	{
		int offset, add, length;

		BOOL wow64 = (vm::read_i16(process, base + 0x12) == 62) ? 0 : 1;
		if (wow64)
		{
			offset = 0x20, add = 0x10, length = 0x04;
		}
		else
		{
			offset = 0x40, add = 0x18, length = 0x08;
		}

		QWORD str_tab = get_dyn_address(process, base, 5);
		QWORD sym_tab = get_dyn_address(process, base, 6);

		sym_tab += add;

		uint32_t st_name = 1;
		do
		{
			char sym_name[120]{};
			if (vm::read(process, str_tab + st_name, &sym_name, sizeof(sym_name)) == -1)
				break;
		
			if (strcmpi_imp(sym_name, export_name) == 0)
			{
				vm::read(process, sym_tab + length, &sym_tab, length);
				return sym_tab + base;
			}
			sym_tab += add;
		} while (vm::read(process, sym_tab, &st_name, sizeof(st_name)) != -1);

		return 0;
	}

	inline PVOID dump_module(vm_handle process, QWORD base, VM_MODULE_TYPE module_type)
	{
		Elf64_Ehdr ehdr;
		vm::read(process, base, &ehdr, sizeof(ehdr));
		QWORD module_size = (ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum));

		if (module_size == 0)
		{
			return 0;
		}

		QWORD dump = (QWORD)malloc(module_size + 16);

		if (dump == 0)
		{
			return 0;
		}

		*(QWORD*)(dump + 0x00) = base;
		*(QWORD*)(dump + 0x08) = module_size;

		dump += 16;

		if (!vm::read(process, base, (PVOID)dump, module_size))
		{
			dump -= 16;

			free((PVOID)dump);
			return 0;
		}

		return (PVOID)dump;
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

	inline QWORD scan_pattern(PVOID dumped_module, PCSTR pattern, PCSTR mask, QWORD length)
	{
		QWORD base    = *(QWORD*)((QWORD)dumped_module - 16);
		QWORD size    = *(QWORD*)((QWORD)dumped_module - 8);
		QWORD address = utils::FindPatternEx((QWORD)dumped_module, size - length, (BYTE*)pattern, (char*)mask);
		if (address)
		{
			return (address - (QWORD)dumped_module) + base;
		}
		return 0;
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


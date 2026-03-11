/*
 * Code Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Functions cut and pasted from
 *
 *   git://github.com/mjg59/shim.git
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 *
 * This file is a functional simplification of Original code from TianoCore
 * (http://tianocore.sf.net)
 *
 *   MdePkg/Library/BasePeCoffLib/BasePeCoff.c
 *
 * Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
 * Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
 * This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php.
 *
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 */
#include <stdio.h>

#include "uefi.h"
#include "pecoff.h"
	
EFI_STATUS
pecoff_read_header(struct PE_COFF_LOADER_IMAGE_CONTEXT *context, void *data)
{
	struct EFI_IMAGE_DOS_HEADER *DosHdr = data;
	union EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (union EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		fprintf(stderr, "Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
	    PEHdr->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		fprintf(stderr, "Only IA32 or X64 images supported\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;
	if (PEHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
		context->ImageSize = (UINT64)PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
		context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
		context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
		context->SecDir = (struct EFI_IMAGE_DATA_DIRECTORY *)
			&PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
		context->FileAlignment = PEHdr->Pe32Plus.OptionalHeader.FileAlignment;
	} else if (PEHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		context->ImageAddress = PEHdr->Pe32.OptionalHeader.ImageBase;
		context->ImageSize = (UINT64)PEHdr->Pe32.OptionalHeader.SizeOfImage;
		context->SizeOfHeaders = PEHdr->Pe32.OptionalHeader.SizeOfHeaders;
		context->EntryPoint = PEHdr->Pe32.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->NumberOfRvaAndSizes = PEHdr->Pe32.OptionalHeader.NumberOfRvaAndSizes;
		context->SecDir = (struct EFI_IMAGE_DATA_DIRECTORY *)
			&PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
		context->FileAlignment = PEHdr->Pe32.OptionalHeader.FileAlignment;
	}

	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;
	context->FirstSection = (struct EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr
		+ PEHdr->Pe32.FileHeader.SizeOfOptionalHeader
		+ sizeof(UINT32)
		+ sizeof(struct EFI_IMAGE_FILE_HEADER));

	if (context->SecDir->VirtualAddress >= context->ImageSize) {
		fprintf(stderr, "secdir vaddr 0x%x >= ImageSize 0x%x\n",
			context->SecDir->VirtualAddress, context->ImageSize);
		fprintf(stderr, "Malformed security header\n");
	}

	return EFI_SUCCESS;
}

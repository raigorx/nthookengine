#include "stdafx.h"
#include "distorm.h"
#include <stdlib.h>
#include <stdlib.h>
#include <Windows.h>

DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva);
VOID AddFunctionToLog(FILE *Log, BYTE *FileBuf, DWORD FuncRVA);
VOID GetInstructionString(char *Str, _DecodedInst *Instr);

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc < 2) return 0;

	//
	// Open log file
	//

	FILE *Log = NULL; 
	
	if (_tfopen_s(&Log, argv[2], _T("w")) != 0)
		return 0;

	//
	// Open PE file
	//

	HANDLE hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		fclose(Log);
		return 0;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);

	BYTE *FileBuf = new BYTE [FileSize];

	DWORD BRW;

	if (FileBuf)
		ReadFile(hFile, FileBuf, FileSize, &BRW, NULL);

	CloseHandle(hFile);

	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *) FileBuf;
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *) ((FileBuf != NULL ?
		pDosHeader->e_lfanew : 0) + (ULONG_PTR) FileBuf);

	if (!FileBuf || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		pNtHeaders->Signature != IMAGE_NT_SIGNATURE ||
		pNtHeaders->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		fclose(Log);
		if (FileBuf)
			delete FileBuf;
		return 0;
	}

	//
	// Walk through export dir's functions
	//

	DWORD ET_RVA = pNtHeaders->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	IMAGE_EXPORT_DIRECTORY *pExportDir = (IMAGE_EXPORT_DIRECTORY *) 
		(RvaToOffset(pNtHeaders, ET_RVA) + (ULONG_PTR) FileBuf);

	DWORD *pFunctions = (DWORD *) (RvaToOffset(pNtHeaders,
		pExportDir->AddressOfFunctions) + (ULONG_PTR) FileBuf);

	for (DWORD x = 0; x < pExportDir->NumberOfFunctions; x++)
	{
		if (pFunctions[x] == 0) continue;

		AddFunctionToLog(Log, FileBuf, pFunctions[x]);
	}

	fclose(Log);
	delete FileBuf;

	return 0;
}

//
// This function adds to the log the instructions
// at the beginning of each function which are going
// to be overwritten by the hook jump
//

VOID AddFunctionToLog(FILE *Log, BYTE *FileBuf, DWORD FuncRVA)
{

#define MAX_INSTRUCTIONS 100

	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)
		((*(IMAGE_DOS_HEADER *) FileBuf).e_lfanew + (ULONG_PTR) FileBuf);

	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

#ifdef _M_IX86

	_DecodeType dt = Decode32Bits;
	
#define JUMP_SIZE 10 // worst case scenario

#else ifdef _M_AMD64
	
	_DecodeType dt = Decode64Bits;

#define JUMP_SIZE 14 // worst case scenario

#endif

	_OffsetType offset = 0;

	res = distorm_decode(offset,	// offset for buffer, e.g. 0x00400000
		(const BYTE *) &FileBuf[RvaToOffset(pNtHeaders, FuncRVA)], 
		50,							// function size (code size to disasm) 
		dt,							// x86 or x64?
		decodedInstructions,		// decoded instr
		MAX_INSTRUCTIONS,			// array size
		&decodedInstructionsCount	// how many instr were disassembled?
		);

	if (res == DECRES_INPUTERR)
		return;

	DWORD InstrSize = 0;

	for (UINT x = 0; x < decodedInstructionsCount; x++)
	{
		if (InstrSize >= JUMP_SIZE)
			break;

		InstrSize += decodedInstructions[x].size;

		char Instr[100];
		GetInstructionString(Instr, &decodedInstructions[x]);

		fprintf(Log, "%s\n", Instr);
	}

	fprintf(Log, "\n\n\n");
}

VOID GetInstructionString(char *Str, _DecodedInst *Instr)
{
	wsprintfA(Str, "%s %s", Instr->mnemonic.p, Instr->operands.p);
	_strlwr_s(Str, 100);
}

DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva)
{
	DWORD Offset = Rva, Limit;
	IMAGE_SECTION_HEADER *Img;
	WORD i;

	Img = IMAGE_FIRST_SECTION(NT);

	if (Rva < Img->PointerToRawData)
		return Rva;

	for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
	{
		if (Img[i].SizeOfRawData)
			Limit = Img[i].SizeOfRawData;
		else
			Limit = Img[i].Misc.VirtualSize;

		if (Rva >= Img[i].VirtualAddress &&
			Rva < (Img[i].VirtualAddress + Limit))
		{
			if (Img[i].PointerToRawData != 0)
			{
				Offset -= Img[i].VirtualAddress;
				Offset += Img[i].PointerToRawData;
			}

			return Offset;
		}
	}

	return NULL;
}
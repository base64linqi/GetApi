#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "getopt.h"

#define OPTIONS "ho:l"

// dword[3c] = PE header offset

#pragma pack(push,1)
/* Portable EXE header */
struct Header
{
	uint32_t Magic;
	uint16_t CPUType;
	uint16_t Sections;
	uint32_t TimeDataStamp;
	uint32_t SymbolTblOfs;
	uint32_t Symbols;
	uint16_t NTHdrSize;
	uint16_t Flags;
	uint16_t Magic2;
	uint8_t LMajor;
	uint8_t LMinor;
	uint32_t CodeSize;
	uint32_t DataSize;
	uint32_t BssSize;
	uint32_t EntryPointRVA;
	uint32_t BaseOfCode;
};

struct HeaderData
{
	uint32_t BaseOfData;
	uint32_t ImageBase;
	uint32_t SectionAlign;
	uint32_t FileAlign;
	uint16_t OSMajor;
	uint16_t OSMinor;
	uint16_t ImageMajor;
	uint16_t ImageMinor;
	uint16_t SubSystMajor;
	uint16_t SubSystMinor;
	uint32_t Win32Version;
	uint32_t ImageSize;
	uint32_t HeaderSize;
	uint32_t FileChecksum;
	uint16_t SubSystem;
	uint16_t DLLFlags;
	uint32_t StackReserveSize;
	uint32_t StackCommitSize;
	uint32_t HeapReserveSize;
	uint32_t HeapCommitSize;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
};

struct Entry{
	uint32_t RVA;
	uint32_t size;
};

struct Directory
{
	struct Entry ExportTable;
	struct Entry ImportTable;
	struct Entry ResourceTable;
	struct Entry ExceptionTable;
	struct Entry CertTable;
	struct Entry RelocTable;
	struct Entry Debug;
	struct Entry Arch;
	struct Entry GlobalPtr;
	struct Entry TLSTable;
	struct Entry LoadConfig;
	struct Entry BoundImport;
	struct Entry IAT;
	struct Entry DelayImportDesc;
	struct Entry CLRRuntimeHeader;
	struct Entry Res1;
};

struct PEObject
{
	uint8_t Name[8];
	uint32_t VirtualSize;
	uint32_t RVA;
	uint32_t PhysicalSize;
	uint32_t PhysicalOffset;
	uint32_t RelocPtr;
	uint32_t LineNumbPtr;
	uint16_t NReloc;
	uint16_t NLineNumb;
	uint32_t Flags;
};

struct ImportEntry
{
	uint32_t ImpFlags; //LookupTableRVA;
	uint32_t DateTime;
	uint16_t MajVer;
	uint16_t MinVer;
	uint32_t NameRVA;
	uint32_t ImpTabRVA;
};

#pragma pack(pop)

struct Safe_Unsafe_Set
{
	char unsafe_function[50][50];
	char unsafe_library[50][50];
	int count;
	char recommended[1000];
	int detected[50];
	int detected_count;
};

struct Safe_Unsafe_Set unsafe_sets[21];
int unsafe_count = 21;

void init()
{
	strcpy_s(unsafe_sets[0].unsafe_function[0], "strcpy");
	strcpy_s(unsafe_sets[0].unsafe_function[1], "strcpyA");
	strcpy_s(unsafe_sets[0].unsafe_function[2], "strcpyW");
	strcpy_s(unsafe_sets[0].unsafe_function[3], "wcscpy");
	strcpy_s(unsafe_sets[0].unsafe_function[4], "_tcscpy");
	strcpy_s(unsafe_sets[0].unsafe_function[5], "_mbscpy");
	strcpy_s(unsafe_sets[0].unsafe_function[6], "StrCpy");
	strcpy_s(unsafe_sets[0].unsafe_function[7], "StrCpyA");
	strcpy_s(unsafe_sets[0].unsafe_function[8], "StrCpyW");
	strcpy_s(unsafe_sets[0].unsafe_function[9], "lstrcpy");
	strcpy_s(unsafe_sets[0].unsafe_function[10], "lstrcpyA");
	strcpy_s(unsafe_sets[0].unsafe_function[11], "lstrcpyW");
	strcpy_s(unsafe_sets[0].unsafe_function[12], "_tccpy");
	strcpy_s(unsafe_sets[0].unsafe_function[13], "_mbccpy");
	strcpy_s(unsafe_sets[0].unsafe_function[14], "_ftcscpy");
	strcpy_s(unsafe_sets[0].unsafe_function[15], "strncpy");
	strcpy_s(unsafe_sets[0].unsafe_function[16], "wcsncpy");
	strcpy_s(unsafe_sets[0].unsafe_function[17], "_tcsncpy");
	strcpy_s(unsafe_sets[0].unsafe_function[18], "_mbsncpy");
	strcpy_s(unsafe_sets[0].unsafe_function[19], "_mbsnbcpy");
	strcpy_s(unsafe_sets[0].unsafe_function[20], "StrCpyN");
	strcpy_s(unsafe_sets[0].unsafe_function[21], "StrCpyNA");
	strcpy_s(unsafe_sets[0].unsafe_function[22], "StrCpyNW");
	strcpy_s(unsafe_sets[0].unsafe_function[23], "StrNCpy");
	strcpy_s(unsafe_sets[0].unsafe_function[24], "strcpynA");
	strcpy_s(unsafe_sets[0].unsafe_function[25], "StrNCpyA");
	strcpy_s(unsafe_sets[0].unsafe_function[26], "StrNCpyW");
	strcpy_s(unsafe_sets[0].unsafe_function[27], "lstrcpyn");
	strcpy_s(unsafe_sets[0].unsafe_function[28], "lstrcpynA");
	strcpy_s(unsafe_sets[0].unsafe_function[29], "lstrcpynW");
	strcpy_s(unsafe_sets[0].recommended, "应替换为strcpy_s");
	unsafe_sets[0].count = 30;
	
	strcpy_s(unsafe_sets[1].unsafe_function[0], "strcat");
	strcpy_s(unsafe_sets[1].unsafe_function[1], "strcatA");
	strcpy_s(unsafe_sets[1].unsafe_function[2], "strcatW");
	strcpy_s(unsafe_sets[1].unsafe_function[3], "wcscat");
	strcpy_s(unsafe_sets[1].unsafe_function[4], "_tcscat");
	strcpy_s(unsafe_sets[1].unsafe_function[5], "_mbscat");
	strcpy_s(unsafe_sets[1].unsafe_function[6], "StrCat");
	strcpy_s(unsafe_sets[1].unsafe_function[7], "StrCatA");
	strcpy_s(unsafe_sets[1].unsafe_function[8], "StrCatW");
	strcpy_s(unsafe_sets[1].unsafe_function[9], "lstrcat");
	strcpy_s(unsafe_sets[1].unsafe_function[10], "lstrcatA");
	strcpy_s(unsafe_sets[1].unsafe_function[11], "lstrcatW");
	strcpy_s(unsafe_sets[1].unsafe_function[12], "StrCatBuff");
	strcpy_s(unsafe_sets[1].unsafe_function[13], "StrCatBuffA");
	strcpy_s(unsafe_sets[1].unsafe_function[14], "StrCatBuffW");
	strcpy_s(unsafe_sets[1].unsafe_function[15], "StrCatChainW");
	strcpy_s(unsafe_sets[1].unsafe_function[16], "_tccat");
	strcpy_s(unsafe_sets[1].unsafe_function[17], "_mbccat");
	strcpy_s(unsafe_sets[1].unsafe_function[18], "_ftcscat");
	strcpy_s(unsafe_sets[1].unsafe_function[19], "strncat");
	strcpy_s(unsafe_sets[1].unsafe_function[20], "wcsncat");
	strcpy_s(unsafe_sets[1].unsafe_function[21], "_tcsncat");
	strcpy_s(unsafe_sets[1].unsafe_function[22], "_mbsncat");
	strcpy_s(unsafe_sets[1].unsafe_function[23], "_mbsnbcat");
	strcpy_s(unsafe_sets[1].unsafe_function[24], "StrCatN");
	strcpy_s(unsafe_sets[1].unsafe_function[25], "StrCatNA");
	strcpy_s(unsafe_sets[1].unsafe_function[26], "StrCatNW");
	strcpy_s(unsafe_sets[1].unsafe_function[27], "StrNCat");
	strcpy_s(unsafe_sets[1].unsafe_function[28], "StrNCatA");
	strcpy_s(unsafe_sets[1].unsafe_function[29], "StrNCatW");
	strcpy_s(unsafe_sets[1].unsafe_function[30], "lstrncat");
	strcpy_s(unsafe_sets[1].unsafe_function[31], "lstrcatnA");
	strcpy_s(unsafe_sets[1].unsafe_function[32], "lstrcatnW");
	strcpy_s(unsafe_sets[1].unsafe_function[33], "lstrcatn");
	strcpy_s(unsafe_sets[1].recommended, "应替换为strcat_s");
	unsafe_sets[1].count = 34;
	
	strcpy_s(unsafe_sets[2].unsafe_function[0], "sprintfW");
	strcpy_s(unsafe_sets[2].unsafe_function[1], "sprintfA");
	strcpy_s(unsafe_sets[2].unsafe_function[2], "wsprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[3], "wsprintfW");
	strcpy_s(unsafe_sets[2].unsafe_function[4], "wsprintfA");
	strcpy_s(unsafe_sets[2].unsafe_function[5], "sprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[6], "swprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[7], "_stprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[8], "wvsprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[9], "wvsprintfA");
	strcpy_s(unsafe_sets[2].unsafe_function[10], "wvsprintfW");
	strcpy_s(unsafe_sets[2].unsafe_function[11], "vsprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[12], "_vstprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[13], "vswprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[14], "wnsprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[15], "wnsprintfA");
	strcpy_s(unsafe_sets[2].unsafe_function[16], "wnsprintfW");
	strcpy_s(unsafe_sets[2].unsafe_function[17], "_snwprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[18], "snprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[19], "sntprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[20], "_vsnprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[21], "vsnprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[22], "_vsnwprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[23], "_vsntprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[24], "wvnsprintf");
	strcpy_s(unsafe_sets[2].unsafe_function[25], "wvnsprintfA");
	strcpy_s(unsafe_sets[2].unsafe_function[26], "wvnsprintfW");
	strcpy_s(unsafe_sets[2].recommended, "应替换为sprintf_s");
	unsafe_sets[2].count = 27;
	
	strcpy_s(unsafe_sets[3].unsafe_function[0], "_snwprintf");
	strcpy_s(unsafe_sets[3].unsafe_function[1], "_snprintf");
	strcpy_s(unsafe_sets[3].unsafe_function[2], "_sntprintf");
	strcpy_s(unsafe_sets[3].unsafe_function[3], "nsprintf");
	strcpy_s(unsafe_sets[3].recommended, "应替换为_snprintf_s or _snwprintf_s");
	unsafe_sets[3].count = 4;
	
	strcpy_s(unsafe_sets[4].unsafe_function[0], "wvsprintf");
	strcpy_s(unsafe_sets[4].unsafe_function[1], "wvsprintfA");
	strcpy_s(unsafe_sets[4].unsafe_function[2], "wvsprintfW");
	strcpy_s(unsafe_sets[4].unsafe_function[3], "vsprintf");
	strcpy_s(unsafe_sets[4].unsafe_function[4], "_vstprintf");
	strcpy_s(unsafe_sets[4].unsafe_function[5], "vswprintf");
	strcpy_s(unsafe_sets[4].recommended, "应替换为_vstprintf_s");
	unsafe_sets[4].count = 6;
	
	strcpy_s(unsafe_sets[5].unsafe_function[0], "_vsnprintf");
	strcpy_s(unsafe_sets[5].unsafe_function[1], "_vsnwprintf");
	strcpy_s(unsafe_sets[5].unsafe_function[2], "_vsntprintf");
	strcpy_s(unsafe_sets[5].unsafe_function[3], "wvnsprintf");
	strcpy_s(unsafe_sets[5].unsafe_function[4], "wvnsprintfA");
	strcpy_s(unsafe_sets[5].unsafe_function[5], "wvnsprintfW");
	strcpy_s(unsafe_sets[5].recommended, "应替换为vsntprintf_s");
	unsafe_sets[5].count = 6;
	
	strcpy_s(unsafe_sets[6].unsafe_function[0], "strncpy");
	strcpy_s(unsafe_sets[6].unsafe_function[1], "wcsncpy");
	strcpy_s(unsafe_sets[6].unsafe_function[2], "_tcsncpy");
	strcpy_s(unsafe_sets[6].unsafe_function[3], "_mbsncpy");
	strcpy_s(unsafe_sets[6].unsafe_function[4], "_mbsnbcpy");
	strcpy_s(unsafe_sets[6].unsafe_function[5], "StrCpyN");
	strcpy_s(unsafe_sets[6].unsafe_function[6], "StrCpyNA");
	strcpy_s(unsafe_sets[6].unsafe_function[7], "StrCpyNW");
	strcpy_s(unsafe_sets[6].unsafe_function[8], "StrNCpy");
	strcpy_s(unsafe_sets[6].unsafe_function[9], "strcpynA");
	strcpy_s(unsafe_sets[6].unsafe_function[10], "StrNCpyA");
	strcpy_s(unsafe_sets[6].unsafe_function[11], "StrNCpyW");
	strcpy_s(unsafe_sets[6].unsafe_function[12], "lstrcpyn");
	strcpy_s(unsafe_sets[6].unsafe_function[13], "lstrcpynA");
	strcpy_s(unsafe_sets[6].unsafe_function[14], "lstrcpynW");
	strcpy_s(unsafe_sets[6].unsafe_function[15], "_fstrncpy");
	strcpy_s(unsafe_sets[6].recommended, "应替换为strncpy_s");
	unsafe_sets[6].count = 16;
	
	strcpy_s(unsafe_sets[7].unsafe_function[0], "strncat");
	strcpy_s(unsafe_sets[7].unsafe_function[1], "wcsncat");
	strcpy_s(unsafe_sets[7].unsafe_function[2], "_tcsncat");
	strcpy_s(unsafe_sets[7].unsafe_function[3], "_mbsncat");
	strcpy_s(unsafe_sets[7].unsafe_function[4], "_mbsnbcat");
	strcpy_s(unsafe_sets[7].unsafe_function[5], "StrCatN");
	strcpy_s(unsafe_sets[7].unsafe_function[6], "StrCatNA");
	strcpy_s(unsafe_sets[7].unsafe_function[7], "StrCatNW");
	strcpy_s(unsafe_sets[7].unsafe_function[8], "StrNCat");
	strcpy_s(unsafe_sets[7].unsafe_function[9], "StrNCatA");
	strcpy_s(unsafe_sets[7].unsafe_function[10], "StrNCatW");
	strcpy_s(unsafe_sets[7].unsafe_function[11], "lstrncat");
	strcpy_s(unsafe_sets[7].unsafe_function[12], "lstrcatnA");
	strcpy_s(unsafe_sets[7].unsafe_function[13], "lstrcatnW");
	strcpy_s(unsafe_sets[7].unsafe_function[14], "lstrcatn");
	strcpy_s(unsafe_sets[7].unsafe_function[15], "_fstrncat");
	strcpy_s(unsafe_sets[7].recommended, "应替换为strncat_s");
	unsafe_sets[7].count = 16;
	
	strcpy_s(unsafe_sets[8].unsafe_function[0], "strtok");
	strcpy_s(unsafe_sets[8].unsafe_function[1], "_tcstok");
	strcpy_s(unsafe_sets[8].unsafe_function[2], "wcstok");
	strcpy_s(unsafe_sets[8].unsafe_function[3], "_mbstok");
	strcpy_s(unsafe_sets[8].recommended, "应替换为strtok_s");
	unsafe_sets[8].count = 4;
	
	strcpy_s(unsafe_sets[9].unsafe_function[0], "makepath");
	strcpy_s(unsafe_sets[9].unsafe_function[1], "_tmakepath");
	strcpy_s(unsafe_sets[9].unsafe_function[2], "_makepath");
	strcpy_s(unsafe_sets[9].unsafe_function[3], "_wmakepath");
	strcpy_s(unsafe_sets[9].recommended, "应替换为_makepath_s");
	unsafe_sets[9].count = 4;
	
	strcpy_s(unsafe_sets[10].unsafe_function[0], "_splitpath");
	strcpy_s(unsafe_sets[10].unsafe_function[1], "_tsplitpath");
	strcpy_s(unsafe_sets[10].unsafe_function[2], "_wsplitpath");
	strcpy_s(unsafe_sets[10].unsafe_function[3], "_wmakepath");
	strcpy_s(unsafe_sets[10].recommended, "应替换为_splitpath_s");
	unsafe_sets[10].count = 4;
	
	strcpy_s(unsafe_sets[11].unsafe_function[0], "scanf");
	strcpy_s(unsafe_sets[11].unsafe_function[1], "wscanf");
	strcpy_s(unsafe_sets[11].unsafe_function[2], "_tscanf");
	strcpy_s(unsafe_sets[11].unsafe_function[3], "sscanf");
	strcpy_s(unsafe_sets[11].unsafe_function[4], "swscanf");
	strcpy_s(unsafe_sets[11].unsafe_function[5], "_stscanf");
	strcpy_s(unsafe_sets[11].recommended, "应替换为sscanf_s");
	unsafe_sets[11].count = 6;
	
	strcpy_s(unsafe_sets[12].unsafe_function[0], "snscanf");
	strcpy_s(unsafe_sets[12].unsafe_function[1], "snwscanf");
	strcpy_s(unsafe_sets[12].unsafe_function[2], "_sntscanf");
	strcpy_s(unsafe_sets[12].recommended, "应替换为_snscanf_s");
	unsafe_sets[12].count = 3;
	
	strcpy_s(unsafe_sets[13].unsafe_function[0], "_itoa");
	strcpy_s(unsafe_sets[13].unsafe_function[1], "_itow");
	strcpy_s(unsafe_sets[13].unsafe_function[2], "_i64toa");
	strcpy_s(unsafe_sets[13].unsafe_function[3], "_i64tow");
	strcpy_s(unsafe_sets[13].unsafe_function[4], "_ui64toa");
	strcpy_s(unsafe_sets[13].unsafe_function[5], "_ui64tot");
	strcpy_s(unsafe_sets[13].unsafe_function[6], "_ui64tow");
	strcpy_s(unsafe_sets[13].unsafe_function[7], "_ultoa");
	strcpy_s(unsafe_sets[13].unsafe_function[8], "_ultot");
	strcpy_s(unsafe_sets[13].unsafe_function[9], "_ultow");
	strcpy_s(unsafe_sets[13].recommended, "应替换为_itoa_s, _itow_s");
	unsafe_sets[13].count = 10;
	
	strcpy_s(unsafe_sets[14].unsafe_function[0], "gets");
	strcpy_s(unsafe_sets[14].unsafe_function[1], "_getts");
	strcpy_s(unsafe_sets[14].unsafe_function[2], "_gettws");
	strcpy_s(unsafe_sets[14].recommended, "应替换为gets_s");
	unsafe_sets[14].count = 3;
	
	strcpy_s(unsafe_sets[15].unsafe_function[0], "IsBadWritePtr");
	strcpy_s(unsafe_sets[15].unsafe_function[1], "IsBadHugeWritePtr");
	strcpy_s(unsafe_sets[15].unsafe_function[2], "IsBadReadPtr");
	strcpy_s(unsafe_sets[15].unsafe_function[3], "IsBadHugeReadPtr");
	strcpy_s(unsafe_sets[15].unsafe_function[4], "IsBadCodePtr");
	strcpy_s(unsafe_sets[15].unsafe_function[5], "IsBadStringPtr");
	strcpy_s(unsafe_sets[15].recommended, "These functions can mask errors, and there are no replacement functions. You should rewrite the code to avoid using these functions. If you need to avoid a crash, wrap your usage of the pointer with __try/__except. Doing this can easily hide bugs; you should do this only in areas where it is absolutely critical to avoid a crash (such as crash recovery code) and where you have a reasonable explanation for why the data you're looking at might be invalid. You should also not catch all exceptions, but only types that you know about. Catching all exceptions is just as bad as using IsBad*Ptr.\n\nFor IsBadWritePtr, filling the destination buffer using memset is a preferred way to validate that output buffers are valid and large enough to hold the amount of space that the caller claims they provided.");
	unsafe_sets[15].count = 6;
	
	strcpy_s(unsafe_sets[16].unsafe_function[0], "CharToOem");
	strcpy_s(unsafe_sets[16].unsafe_function[1], "CharToOemA");
	strcpy_s(unsafe_sets[16].unsafe_function[2], "CharToOemW");
	strcpy_s(unsafe_sets[16].unsafe_function[3], "OemToChar");
	strcpy_s(unsafe_sets[16].unsafe_function[4], "OemToCharA");
	strcpy_s(unsafe_sets[16].unsafe_function[5], "OemToCharW");
	strcpy_s(unsafe_sets[16].unsafe_function[6], "CharToOemBuffA");
	strcpy_s(unsafe_sets[16].unsafe_function[7], "CharToOemBuffW");
	strcpy_s(unsafe_sets[16].recommended, "应替换为WideCharToMultiByte");
	unsafe_sets[16].count = 8;
	
	strcpy_s(unsafe_sets[17].unsafe_function[0], "alloca");
	strcpy_s(unsafe_sets[17].unsafe_function[1], "_alloca");
	strcpy_s(unsafe_sets[17].recommended, "应替换为SafeAllocA");
	unsafe_sets[17].count = 2;
	
	strcpy_s(unsafe_sets[18].unsafe_function[0], "strlen");
	strcpy_s(unsafe_sets[18].unsafe_function[1], "wcslen");
	strcpy_s(unsafe_sets[18].unsafe_function[2], "_mbslen");
	strcpy_s(unsafe_sets[18].unsafe_function[3], "_mbstrlen");
	strcpy_s(unsafe_sets[18].unsafe_function[4], "StrLen");
	strcpy_s(unsafe_sets[18].unsafe_function[5], "lstrlen");
	strcpy_s(unsafe_sets[18].recommended, "应替换为strnlen_s");
	unsafe_sets[18].count = 6;
	
	strcpy_s(unsafe_sets[19].unsafe_function[0], "memcpy");
	strcpy_s(unsafe_sets[19].unsafe_function[1], "RtlCopyMemory");
	strcpy_s(unsafe_sets[19].unsafe_function[2], "CopyMemory");
	strcpy_s(unsafe_sets[19].unsafe_function[3], "wmemcpy");
	strcpy_s(unsafe_sets[19].recommended, "应替换为memcpy_s, wmemcpy_s");
	unsafe_sets[19].count = 4;
	
	strcpy_s(unsafe_sets[20].unsafe_function[0], "ChangeWindowMessageFilter");
	strcpy_s(unsafe_sets[20].recommended, "This function is not recommended because it has process-wide scope. You can use ChangeWindowMessageFilterEx to control access for specific windows, but give careful consideration to any message filtering changes.");
	unsafe_sets[20].count = 1;
	


}

int main(int argc, char *argv[])
{
	int c;
	int is_print_library = 0;
	FILE *outfp = stdout; 
	FILE *exe_fp; 
	uint32_t pe_offset;
	struct Header header;
	struct HeaderData headerData; 
	struct Directory directory; 
	struct PEObject object;
	uint32_t import_table_offset = 0;
	uint32_t import_table_size = 0;
	uint32_t import_table_RVA = 0;
	int i, cnt = 0;
	int j, k;
	int total_count = 0;
	while((c = getopt(argc, argv, OPTIONS)) >= 0)
	{
		switch (c)
		{
		case 'o':
			outfp = fopen(optarg, "wt");
			if(outfp == NULL)
			{
				printf("Open outfile error!\n");
				return 1;
			}
			break;
		case 'h':
			printf("Usage: %s exefile [-o outfile] [-l]\n", argv[0]);
			printf("---------------------Bangcle 林奇----------------------------------\n");
			printf("  _______  _______ .___________.    ___      .______    __  \n");
			printf(" /  _____||   ____||           |   /   \\     |   _  \\  |  | \n");
			printf("|  |  __  |  |__   `---|  |----`  /  ^  \\    |  |_)  | |  | \n");
			printf("|  | |_ | |   __|      |  |      /  /_\\  \\   |   ___/  |  | \n");
			printf("|  |__| | |  |____     |  |     /  _____  \\  |  |      |  | \n");
			printf(" \\______| |_______|    |__|    /__/     \\__\\ | _|      |__|\n");
			return 1;
			break;
		case 'l':
			is_print_library = 1;
			break;
		}
	}
	if (argc == optind)
	{
		printf("Usage: %s exefile [-o outfile] [-l]\n", argv[0]);
		printf("---------------------Bangcle 林奇----------------------------------\n");
		printf("  _______  _______ .___________.    ___      .______    __  \n");
		printf(" /  _____||   ____||           |   /   \\     |   _  \\  |  | \n");
		printf("|  |  __  |  |__   `---|  |----`  /  ^  \\    |  |_)  | |  | \n");
		printf("|  | |_ | |   __|      |  |      /  /_\\  \\   |   ___/  |  | \n");
		printf("|  |__| | |  |____     |  |     /  _____  \\  |  |      |  | \n");
		printf(" \\______| |_______|    |__|    /__/     \\__\\ | _|      |__|\n");
		return 1;
	}
	init();
	printf("Input file:%s\n", argv[optind]);
	exe_fp = fopen(argv[optind], "rb");

	if(exe_fp == NULL)
	{
		printf("Open exefile error!\n");
		printf("---------------------Bangcle 林奇----------------------------------\n");
		printf("  _______  _______ .___________.    ___      .______    __  \n");
		printf(" /  _____||   ____||           |   /   \\     |   _  \\  |  | \n");
		printf("|  |  __  |  |__   `---|  |----`  /  ^  \\    |  |_)  | |  | \n");
		printf("|  | |_ | |   __|      |  |      /  /_\\  \\   |   ___/  |  | \n");
		printf("|  |__| | |  |____     |  |     /  _____  \\  |  |      |  | \n");
		printf(" \\______| |_______|    |__|    /__/     \\__\\ | _|      |__|\n");
		return 1;
	}
	fseek(exe_fp, 0x3C, SEEK_SET);
	fread(&pe_offset, 1, 4, exe_fp);
	fseek(exe_fp, pe_offset, SEEK_SET);
	fread(&header, 1, sizeof(struct Header), exe_fp);
	if (header.Magic != (('E' << 8) + 'P'))
	{
		printf("Invalid exe file!\n");
	}
	fread(&headerData, 1, sizeof(struct HeaderData), exe_fp);
	fread(&directory, 1, sizeof(struct Directory), exe_fp);

	for (i = 0; i < header.Sections; ++i)
	{
		fseek(exe_fp, header.NTHdrSize + pe_offset + 24 + i * sizeof(object), SEEK_SET);
		fread(&object, 1, sizeof(object), exe_fp);
		uint32_t temp = directory.ImportTable.RVA;
		if (object.RVA <= temp && temp < (object.RVA + object.VirtualSize))
		{
			import_table_offset = object.PhysicalOffset;
			import_table_size = object.VirtualSize;
			import_table_RVA = object.RVA;
		}
	}
	if (import_table_offset == 0)
	{
		fprintf(outfp, "No import table!\n");
	}
	else
	{
		uint8_t *import_data = (uint8_t*)malloc(import_table_size);
		fseek(exe_fp, import_table_offset, SEEK_SET);
		fread(import_data, 1, import_table_size, exe_fp);
		struct ImportEntry *imp;
		int rva = import_table_RVA;
		
		for (imp = (struct ImportEntry*)(import_data + directory.ImportTable.RVA - import_table_RVA);
				 imp->NameRVA; imp++)
		{
			char* dll_name = (char*)import_data + imp->NameRVA - import_table_RVA;
			for (i = 0;;++i)
			{
				int temp = *((int*)(import_data + imp->ImpTabRVA + i * 4 - import_table_RVA));
				if (temp == 0)
					break;
				char output[100];
				char* func_name = (char *)import_data - import_table_RVA + temp + 2;
				for(j = 0; j < 21; j++)
				{
					for(k = 0; k < unsafe_sets[j].count; k++)
					{
						if(strcmp(unsafe_sets[j].unsafe_function[k], func_name) == 0)
						{
							strcpy_s(unsafe_sets[j].unsafe_library[k], dll_name);
							unsafe_sets[j].detected[k] = 1;
							unsafe_sets[j].detected_count++;
							total_count++;
						}
					}
				}
				
				if(is_print_library)
					sprintf(output, "%s(%s)", (char *)import_data - import_table_RVA + temp + 2, dll_name);
				else
					sprintf(output, "%s", (char *)import_data - import_table_RVA + temp + 2);
				++cnt;
				fprintf(outfp, "%33s ", output);
				if(cnt % 3 == 0)
					fprintf(outfp, "\n");
				
			}
		}
		free(import_data);
	}
	fclose(exe_fp);
	fprintf(outfp, "\n");
	for(j = 0; j < 21; j++)
	{
		if(unsafe_sets[j].detected_count > 0)
		{
			int count = 0;
			fprintf(outfp, "不安全函数:");
			for(k = 0; k < unsafe_sets[j].count; k++)
			{
				if(unsafe_sets[j].detected[k] > 0)
				{
					if(count > 0)
					{
						fprintf(outfp, ", ");
					}
					if(is_print_library)
						fprintf(outfp, "%s(%s)", unsafe_sets[j].unsafe_function[k], unsafe_sets[j].unsafe_library[k]);
					else
						fprintf(outfp, "%s", unsafe_sets[j].unsafe_function[k]);
					count++;
				}
			}
			fprintf(outfp, ", %s\n", unsafe_sets[j].recommended);
		} 
	}
	if(outfp != stdout)
	{
		fclose(outfp);
	}
	printf("-------------------------------\n该程序不安全函数有%d个,请按照建议或官方建议进行修改\n", total_count);
	printf("---------------------Bangcle 林奇----------------------------------\n");
	printf("  _______  _______ .___________.    ___      .______    __  \n");
	printf(" /  _____||   ____||           |   /   \\     |   _  \\  |  | \n");
	printf("|  |  __  |  |__   `---|  |----`  /  ^  \\    |  |_)  | |  | \n");
	printf("|  | |_ | |   __|      |  |      /  /_\\  \\   |   ___/  |  | \n");
	printf("|  |__| | |  |____     |  |     /  _____  \\  |  |      |  | \n");
	printf(" \\______| |_______|    |__|    /__/     \\__\\ | _|      |__|\n");
	return 0;
}

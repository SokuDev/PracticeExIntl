// Created by PracticeInit Development group on 2023.12.5

// The template was created by PinkySmile on 31/10/2020
//

// clang-format off
// #include "internal/csv_row.hpp"
#include <cstdarg>
#include <cstddef>
#include <istream>
#include <mutex>
#include <string>
#include <type_traits>
#include "UnionCast.hpp"
// clang-format on
// #include "Hash.hpp"
#include "BattleMode.hpp"
#include "Scenes.hpp"
#include "Tamper.hpp"
#include "VTables.hpp"
#include "csv.h"
#include <assert.h>
#include <cstdint>
#include <detours.h>
#include <filesystem>
#include <fstream>
#include <interlockedapi.h>
#include <intrin.h>
#include <iostream>
#include <psapi.h>
#include <shlwapi.h>
#include <unordered_map>
#pragma intrinsic(_ReturnAddress)
#define CUSTOM_UNCOMPRESS_PREFIX (0x7777777777777777)
#define CUSTOM_MACROFONT_PREFIX (0xFFFFFFFFFFFFFFFF)
#define PRACTICE_EX_VERSION_STRING_OFFEST 0xbd070
#define PRACTICE_EX_VERSION_STRING "PracticeEX v2.1.0"
C_ASSERT(sizeof(CUSTOM_UNCOMPRESS_PREFIX) == 8);
std::unordered_map<const char *, std::string> TranslationMap;
void *(__thiscall *ori_std_basic_string_contructor_addr)(void *strObj, const char *cstr) = nullptr;
void *(__thiscall *ori_std_string_contructor_addr)(void *strObj, const char *cstr, size_t cstr_length) = nullptr;
void(WINAPI *oriInitializeSListHead)(PSLIST_HEADER ListHeader) = InitializeSListHead;
static std::filesystem::path dllPath;
static std::filesystem::path macroFontPath;
static size_t bigEndianMacroFontSize;
static void *practiceExBase = nullptr;
static void *originalFun = nullptr;
static bool hooked = false;
static bool initialized = false;
static std::wstring iniPath;
HMODULE practiceExHandle = 0;
HMODULE myHandle;
static int /*SokuLib::Scene*/ (SokuLib::Select::*ogSelectOnProcess)();
#pragma pack(push, 1)
struct compressed_data {
	uint64_t prefix;
	unsigned int big_endian_int;
	char data[];
};
#pragma pack(pop)

// We check if the game version is what we target (in our case, Soku 1.10a).
extern "C" __declspec(dllexport) bool CheckVersion(const BYTE hash[16]) {
	// return memcmp(hash, SokuLib::targetHash, sizeof(SokuLib::targetHash)) == 0;
	return true;
}

void *__fastcall my_std_basic_string_contructor(void *strObj, void *, const char *cstr) {
	auto result = TranslationMap.find(cstr);
	if (result != TranslationMap.end())
		cstr = result->second.c_str();
	return ori_std_basic_string_contructor_addr(strObj, cstr);
}

void *__fastcall my_std_string_contructor(void *strObj, void *, const char *cstr, size_t cstr_len) {
	auto result = TranslationMap.find(cstr);
	if (result != TranslationMap.end()) {
		cstr = result->second.c_str();
		cstr_len = result->second.length();
	}
	return ori_std_string_contructor_addr(strObj, cstr, cstr_len);
}

static int __fastcall EmptyOnProcess(void *) {
	return 0;
}

static int __fastcall CSelect_OnProcess(SokuLib::Select *This) {
	if (!initialized && SokuLib::mainMode == SokuLib::BATTLE_MODE_PRACTICE && practiceExHandle) {
		if (!((bool (*)(HMODULE, HMODULE))(GetProcAddress(practiceExHandle, "Initialize")))(practiceExHandle, myHandle)) {
			std::cout << "Failed to initialize PracticeEx!" << std::endl;
			FreeLibrary(practiceExHandle);
		} else {
			int(__fastcall * &practiceExOgCTitle_OnProcess)(void *) = *(int(__fastcall **)(void *))((char *)practiceExBase + 0xcd068);
			int(__fastcall * old)(void *) = practiceExOgCTitle_OnProcess;
			practiceExOgCTitle_OnProcess = EmptyOnProcess;
			((int(__fastcall *)(void *))((char *)practiceExBase + 0x58750))(NULL);
			practiceExOgCTitle_OnProcess = old;
			std::cout << "Initialized PracticeEx!" << std::endl;
		}
		initialized = true;
	}
	return (This->*ogSelectOnProcess)();
}

static void __declspec(naked) my_10022b90() {
	__asm { // [ebx] = CUSTOM_MACROFONT_PREFIX; jmp originalFun;
		push eax;
		mov eax, (CUSTOM_MACROFONT_PREFIX & 0xFFFFFFFF);
		mov [ebx], eax;
		add ebx, 4;
		mov eax, (CUSTOM_MACROFONT_PREFIX >> 32);
		mov [ebx], eax;
		add ebx, 4;
		mov eax, [bigEndianMacroFontSize];
		mov [ebx], eax;
		sub ebx, 8;
		pop eax;
		jmp originalFun;
	}
}

static int __cdecl my_fun10040a60(char *param_1, int param2, int pattern, void *locale, va_list valist) {
	// std::cout << *(int *)valist << ", " << ((const char **)valist)[1] << ", " << ((int *)valist)[2] << std::endl;
	const char *const localstr = ((const char **)valist)[1];
	char *u8str = nullptr;
	int result = MultiByteToWideChar(CP_ACP, 0, localstr, -1, NULL, 0);
	if (result > 0) {
		wchar_t *wide_str = new wchar_t[result];
		result = MultiByteToWideChar(CP_ACP, 0, localstr, -1, &wide_str[0], result * sizeof(wchar_t));
		if (result > 0) {
			result = WideCharToMultiByte(CP_UTF8, 0, &wide_str[0], -1, NULL, 0, NULL, NULL);
			if (result > 0) {
				u8str = new char[result];
				result = WideCharToMultiByte(CP_UTF8, 0, &wide_str[0], -1, u8str, result, NULL, NULL);
				if (result > 0) {
					((const char **)valist)[1] = u8str;
				} else {
					delete[] u8str;
					u8str = nullptr;
				}
			}
		}
		delete[] wide_str;
	}
	int ret = ((int(__cdecl *)(char *, ...))((char *)practiceExBase + 0x40a60))(param_1, param2, pattern, locale, valist);
	if (u8str)
		delete u8str;
	((const char **)valist)[1] = localstr;
	return ret;
}

int __fastcall my_uncompress(char *dst, const compressed_data *src) {
	unsigned int uncompressed_size = _byteswap_ulong(src->big_endian_int);
	std::cout << "Uncompress data with prefix = 0x" << *(void **)src << ", size = " << uncompressed_size;
	switch (src->prefix) {
	case CUSTOM_MACROFONT_PREFIX:
		std::cout << " (custom macro font)" << std::endl;
		{
			size_t font_size = _byteswap_ulong(bigEndianMacroFontSize);
			auto f = std::ifstream(macroFontPath, std::ios::binary | std::ios::in);
			f.read(dst, font_size);
			f.close();
			return font_size;
		}
	case CUSTOM_UNCOMPRESS_PREFIX:
		std::cout << " (custom uncompressed data)" << std::endl;
		memcpy(dst, src->data, uncompressed_size);
		return uncompressed_size;
	default:
		std::cout << " (original compressed data)" << std::endl;
		return ((int(__fastcall *)(char *, const compressed_data *))((char *)practiceExBase + 0x00026c70))(dst, src);
	}
}

bool overwriteMacroFont(std::filesystem::path path) {
	if (!(std::filesystem::exists(path))) {
		std::cout << path << " is not exists" << std::endl;
		return false;
	}
	if (!(std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path))) {
		std::cout << path << " is not a regular file" << std::endl;
		return false;
	}
	macroFontPath = path;
	bigEndianMacroFontSize = _byteswap_ulong(std::filesystem::file_size(macroFontPath));
	return true;
}

bool overwriteFont(int call_offest, std::filesystem::path path) {
	if (!(std::filesystem::exists(path))) {
		std::cout << path << " is not exists" << std::endl;
		return false;
	}
	if (!(std::filesystem::is_regular_file(path) || std::filesystem::is_symlink(path))) {
		std::cout << path << " is not a regular file" << std::endl;
		return false;
	}

	void *call_addr = (char *)practiceExBase + call_offest;
	unsigned int font_size = std::filesystem::file_size(path);
	std::cout << "Load " << path << std::endl;
	std::ifstream f{path, std::ios::in | std::ios::binary};
	if (f.fail()) {
		std::cout << "Failed to load" << path << std::endl;
		return false;
	}
	DWORD old;
	VirtualProtect((char *)call_addr - 5 * 3, 5 * 3, PAGE_EXECUTE_WRITECOPY, &old);
	// std::cout << *(void **)((char *)call_addr - 5 * 3 + 1) << " " << *(void **)((char *)call_addr - 5 * 2 + 1) << std::endl;
	unsigned int size = sizeof(compressed_data) + font_size;
	compressed_data *font = (compressed_data *)malloc(size);
	font->prefix = CUSTOM_UNCOMPRESS_PREFIX;
	font->big_endian_int = _byteswap_ulong(font_size);
	f.read(font->data, font_size);
	f.close();
	*(void **)((char *)call_addr - 5 * 2 + 1) = font;
	*(int *)((char *)call_addr - 5 * 3 + 1) = size;
	VirtualProtect((char *)call_addr - 5 * 3, 5 * 3, old, &old);
	return true;
}

// https://stackoverflow.com/a/3418285
void replaceAll(std::string &str, const std::string &from, const std::string &to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}

void readCsvAndHook(std::filesystem::path csvPath, bool useUTF8) {
	std::cout << "Load csv " << csvPath << std::endl;
	io::CSVReader<3> csv(csvPath.string());
	csv.read_header(io::ignore_extra_column | io::ignore_missing_column, "Address", "ReferenceAddress", useUTF8 ? "Translation" : "Ascii");
	std::string addressStr, translation, referenceAddressStr = "";
	int count = 0;
	while (csv.read_row(addressStr, referenceAddressStr, translation)) {
		if (referenceAddressStr.length() == 0 && addressStr.length() == 0)
			continue;
		if (translation.length() == 0) {
			std::cout << "Ignore " << addressStr << ", ref: " << referenceAddressStr << std::endl;
			continue;
		}

		char *targetCStr;
		if (referenceAddressStr.length())
			targetCStr = (char *)malloc(translation.length() / (useUTF8 ? 1 : 2) + 1);
		else
			targetCStr = (char *)practiceExBase + stoul(addressStr, nullptr, 16) - 0x10000000;

		if (useUTF8) {
			replaceAll(translation, "\\t", "\t");
			TranslationMap.insert({targetCStr, translation});
			count++;
			if (referenceAddressStr.length() == 0)
				continue;
			strcpy(targetCStr, translation.c_str());
		} else {
			if (translation.find_first_not_of("0123456789abcdefABCDEF ") != std::string::npos) {
				std::cout << "Ignore " << addressStr << ", ref: " << referenceAddressStr << std::endl;
				if (referenceAddressStr.length())
					free(targetCStr);
				continue;
			}
			// std::cout << "Set Translation at " << " (PracticeEx.dll+0x" << addressStr << ")" << std::endl;
			const size_t length = translation.length();
			DWORD old;
			auto targetCStr_ = targetCStr;
			if (referenceAddressStr.length() == 0)
				VirtualProtect(targetCStr, length + 1, PAGE_EXECUTE_WRITECOPY, &old);
			for (int i = 0; i < length; i += 2, targetCStr_++) {
				while (translation[i] == ' ')
					i++;
				if (translation[i] == '\0')
					break;
				char hex[3] = {translation[i], translation[i + 1], '\0'};
				auto byte = strtoul(hex, 0, 16);
				// assert(byte <= 0x7f);
				*targetCStr_ = byte;
			}
			*targetCStr_ = '\0';
			if (referenceAddressStr.length() == 0)
				VirtualProtect(targetCStr, length + 1, old, &old);
		}
		if (referenceAddressStr.length()) {
			DWORD old;
			char **address = (char **)((char *)practiceExBase + stoul(referenceAddressStr, nullptr, 16) - 0x10000000);
			VirtualProtect(address, 4, PAGE_EXECUTE_WRITECOPY, &old);
			*address = targetCStr;
			VirtualProtect(address, 4, old, &old);
		}
		count++;
	}
	std::cout << "Got " << count << " translations" << std::endl;
}

bool overwriteMacroText(std::filesystem::path path) {
	auto path_otf = path;
	path_otf += ".otf";
	auto path_ttf = path;
	path_ttf += ".ttf";
	if (!(overwriteMacroFont(path_otf) || overwriteMacroFont(path_ttf)))
		return false;

	DWORD old;
	originalFun = (char *)practiceExBase + 0x22b90;
	auto fun10022b90_call_addr = (char *)practiceExBase + 0x22dcf;
	VirtualProtect(fun10022b90_call_addr, 5, PAGE_EXECUTE_WRITECOPY, &old);
	SokuLib::TamperNearCall((DWORD)fun10022b90_call_addr, my_10022b90);
	VirtualProtect(fun10022b90_call_addr, 5, old, &old);
	auto fun10040a60_call_addr = (char *)practiceExBase + 0x63735;
	VirtualProtect(fun10040a60_call_addr, 5, PAGE_EXECUTE_WRITECOPY, &old);
	SokuLib::TamperNearCall((DWORD)fun10040a60_call_addr, my_fun10040a60);
	VirtualProtect(fun10040a60_call_addr, 5, old, &old);

	auto path_csv = path;
	path_csv += ".csv";
	if (!std::filesystem::exists(path_csv)) {
		std::cout << path_csv << " is not exists" << std::endl;
		return true;
	}
	if (!(std::filesystem::is_regular_file(path_csv) || std::filesystem::is_symlink(path_csv))) {
		std::cout << path_csv << " is not a regular file" << std::endl;
		return true;
	}

	readCsvAndHook(path_csv, true);
	return true;
}

bool overwriteText(int call_offest, std::filesystem::path path, bool useUTF8) {
	auto path_otf = path;
	path_otf += ".otf";
	auto path_ttf = path;
	path_ttf += ".ttf";
	if (!(overwriteFont(call_offest, path_otf) || overwriteFont(call_offest, path_ttf)))
		return false;

	auto path_csv = path;
	path_csv += ".csv";
	if (!std::filesystem::exists(path_csv)) {
		std::cout << path_csv << " is not exists" << std::endl;
		return true;
	}
	if (!(std::filesystem::is_regular_file(path_csv) || std::filesystem::is_symlink(path_csv))) {
		std::cout << path_csv << " is not a regular file" << std::endl;
		return true;
	}
	readCsvAndHook(path_csv, useUTF8);
	return true;
}

void WINAPI myInitializeSLishHead(PSLIST_HEADER ListHeader) {
	std::cout << "InitializeSLishHead hook trigerred " << (void *)ListHeader << " " << (void *)_ReturnAddress() << std::endl;
	oriInitializeSListHead(ListHeader);

	if (hooked || (unsigned int)ListHeader - (unsigned int)_ReturnAddress() != 0x100cc250u - 0x1006af72u)
		return;

	practiceExBase = (void *)((unsigned int)ListHeader - 0x000cc250u);
	std::cout << "InitializeSLishHead hook in PracticeEx" << std::endl;
	std::cout << "PracticeEx base address: " << practiceExBase << std::endl;
	// static uint16_t ranges[] = {0x0020, 0xD7FF, 0xE000, 0xFFFF, 0}; // Basic Multilingual Plane
	// https://github.com/ocornut/imgui/blob/b81bd7ed984ce095c20a059dd0f4d527e006998f/imgui_draw.cpp#L2976
	static uint16_t ranges[] = {
		0x0020,
		0x00FF, // Basic Latin + Latin Supplement
		0x2000,
		0x206F, // General Punctuation
		0x3000,
		0x30FF, // CJK Symbols and Punctuations, Hiragana, Katakana
		0x31F0,
		0x31FF, // Katakana Phonetic Extensions
		0xFF00,
		0xFFEF, // Half-width characters
		0xFFFD,
		0xFFFD, // Invalid
		0x4e00,
		0x9FAF, // CJK Ideograms
		0,
	};
	DWORD old;
	VirtualProtect((char *)practiceExBase + 0x22b4d, 4, PAGE_EXECUTE_WRITECOPY, &old);
	*(uint16_t **)((char *)practiceExBase + 0x22b4d) = ranges;
	VirtualProtect((char *)practiceExBase + 0x22b4d, 4, old, &old);
	VirtualProtect((char *)practiceExBase + 0x231c4, 4, PAGE_EXECUTE_WRITECOPY, &old);
	*(uint16_t **)((char *)practiceExBase + 0x231c4) = ranges;
	VirtualProtect((char *)practiceExBase + 0x231c4, 4, old, &old);

	overwriteText(0x1bd3, dllPath / "Trigger", GetPrivateProfileIntW(L"PracticeExIntl", L"TriggerUseUTF8", 1, iniPath.c_str()));
	overwriteText(0x1d42, dllPath / "OptionsLeft", GetPrivateProfileIntW(L"PracticeExIntl", L"OptionsLeftUseUTF8", 1, iniPath.c_str()));
	overwriteText(0x1d60, dllPath / "OptionsRight", GetPrivateProfileIntW(L"PracticeExIntl", L"OptionsRightUseUTF8", 1, iniPath.c_str()));
	overwriteText(0x1d7e, dllPath / "Title", GetPrivateProfileIntW(L"PracticeExIntl", L"TitleUseUTF8", 1, iniPath.c_str()));
	overwriteMacroText(dllPath / "Macro");
	//   overwriteFont(0x47b06, font, 0x12 + 19 + fontsize); // unknown
	auto uncompress_call_addr = (char *)practiceExBase + 0x22beb;
	VirtualProtect(uncompress_call_addr, 5, PAGE_EXECUTE_WRITECOPY, &old);
	SokuLib::TamperNearCall((DWORD)uncompress_call_addr, my_uncompress);
	VirtualProtect(uncompress_call_addr, 5, old, &old);

	ori_std_basic_string_contructor_addr = (void *(__thiscall *)(void *, const char *))((char *)practiceExBase + 0x370a0);
	ori_std_string_contructor_addr = (void *(__thiscall *)(void *, const char *, size_t))((char *)practiceExBase + 0x34e20);
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((void **)&ori_std_basic_string_contructor_addr, my_std_basic_string_contructor);
	DetourAttach((void **)&ori_std_string_contructor_addr, my_std_string_contructor);
	DetourDetach((void **)&oriInitializeSListHead, myInitializeSLishHead);
	DetourTransactionCommit();
	FlushInstructionCache(GetCurrentProcess(), nullptr, 0);

	// fix random airtech
	unsigned char replaceEbp1[] = {
		0x85, 0xc0, // test eax,eax
		0x90, 0x90, 0x90, 0x90, 0x90 // nop * 5
	};
	VirtualProtect((char *)practiceExBase + 0x5781b, sizeof(replaceEbp1), PAGE_EXECUTE_WRITECOPY, &old);
	memcpy((char *)practiceExBase + 0x5781b, replaceEbp1, sizeof(replaceEbp1));
	VirtualProtect((char *)practiceExBase + 0x5781b, sizeof(replaceEbp1), old, &old);
	unsigned char replaceEbp2[] = {0x90, 0x90, 0x90}; // nop * 3
	VirtualProtect((char *)practiceExBase + 0x57824, sizeof(replaceEbp2), PAGE_EXECUTE_WRITECOPY, &old);
	memcpy((char *)practiceExBase + 0x57824, replaceEbp2, sizeof(replaceEbp2));
	VirtualProtect((char *)practiceExBase + 0x57824, sizeof(replaceEbp2), PAGE_EXECUTE_WRITECOPY, &old);
	hooked = true;
}

void tryHookPracticeEx(HMODULE hModule) {
	if (practiceExBase)
		return;
#ifdef DEBUG
	FILE *_;
	AllocConsole();
	freopen_s(&_, "CONOUT$", "w", stdout);
	freopen_s(&_, "CONOUT$", "w", stderr);
#endif
	wchar_t wDllPath[1024];
	GetModuleFileNameW(hModule, wDllPath, 1024);
	PathRemoveFileSpecW(wDllPath);
	dllPath = wDllPath;
	iniPath = (dllPath / "PracticeExIntl.ini").wstring();
	wchar_t wPracticeExDllFile[1024];
	GetPrivateProfileStringW(
		L"PracticeExIntl", L"PracticeExFile", L"./PracticeEx-original/PracticeEx.dll", wPracticeExDllFile, sizeof(wPracticeExDllFile), iniPath.c_str());
	std::filesystem::path practiceExDllFile = wPracticeExDllFile;
	if (practiceExDllFile.is_relative())
		practiceExDllFile = dllPath / practiceExDllFile;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	(void(WINAPI *)(PSLIST_HEADER)) DetourAttach((void **)&oriInitializeSListHead, myInitializeSLishHead);
	DetourTransactionCommit();
	FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
	practiceExHandle = LoadLibraryW(practiceExDllFile.wstring().c_str());
	do {
		if (!practiceExHandle) {
			std::cout << "Cannot load PracticeEx! PracticeEx Dll: " << practiceExDllFile << std::endl;
			break;
		}
		MODULEINFO moduleinfo;
		if (!GetModuleInformation(GetCurrentProcess(), practiceExHandle, &moduleinfo, sizeof(moduleinfo))) {
			std::cout << "Cannot get base address of PracticeEx handle" << std::endl;
			break;
		}
		// if ((char *)moduleinfo.lpBaseOfDll + 0xbd070)
		if (PRACTICE_EX_VERSION_STRING_OFFEST + sizeof(PRACTICE_EX_VERSION_STRING) > moduleinfo.SizeOfImage) {
			std::cout << practiceExDllFile << " is not PracticeEx 2.1.0" << std::endl;
			// fail
			break;
		}
		if (memcmp(PRACTICE_EX_VERSION_STRING, (char *)moduleinfo.lpBaseOfDll + PRACTICE_EX_VERSION_STRING_OFFEST, sizeof(PRACTICE_EX_VERSION_STRING)) != 0) {
			std::cout << practiceExDllFile << " is not PracticeEx 2.1.0" << std::endl;
			// fail
			break;
		}
		if (!hooked) {
			std::cout << "Failed to hook " << practiceExBase << "!" << std::endl;
			break;
		}
		assert(practiceExBase == moduleinfo.lpBaseOfDll);
		DWORD old;
		VirtualProtect((PVOID)RDATA_SECTION_OFFSET, RDATA_SECTION_SIZE, PAGE_EXECUTE_WRITECOPY, &old);
		ogSelectOnProcess = SokuLib::TamperDword(&SokuLib::VTable_Select.onProcess, CSelect_OnProcess);
		VirtualProtect((PVOID)RDATA_SECTION_OFFSET, RDATA_SECTION_SIZE, old, &old);
		return;
	} while (false);
	practiceExBase = nullptr;
	practiceExHandle = 0;
	// if (!_initterm_e((_PIFV *)((char *)practiceExBase + 0x0009a37c), (_PIFV *)((char *)practiceExBase + 0x0009a389))) {
	// 	std::cout << "Failed to initalize PracticeEx.dll!" << std::endl;
	// 	FreeLibrary(practiceExHandle);
	// }

	// _initterm((_PVFV *)((char *)practiceExBase + 0x0009a240), (_PVFV *)((char *)practiceExBase + 0x0009a328));
	// // _PVFV *ppfn = (_PVFV *)((char *)practiceExBase + 0x0009a240);
	// // do {
	// // 	if (_PVFV pfn = *++ppfn) {
	// // 		pfn();
	// // 	}
	// // } while (ppfn < (_PVFV *)((char *)practiceExBase + 0x0009a328));
	// // ((int (__cdecl *)(int, int))((char *)practiceExBase + 0x6a7c4))(0,0);
	// if (!((bool (*)(HMODULE, HMODULE))(GetProcAddress(practiceExHandle, "Initialize")))(practiceExHandle, hModule)) {
	// 	std::cout << "Failed to initialize PracticeEx!" << std::endl;
	// 	FreeLibrary(practiceExHandle);
	// 	practiceExBase = nullptr;
	// 	return;
	// }

	// std::cout << "PracticeEx is hooked!" << std::endl;
}

// Called when the mod loader is ready to initialize this module.
// All hooks should be placed here. It's also a good moment to load settings
// from the ini.
extern "C" __declspec(dllexport) bool Initialize(HMODULE hMyModule, HMODULE hParentModule) {
	myHandle = hMyModule;
	tryHookPracticeEx(hMyModule);
	return practiceExBase != nullptr;
}

extern "C" int APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
	// if (fdwReason == DLL_PROCESS_ATTACH) {
	// 	return TRUE;
	// }
	return TRUE;
}

// New mod loader functions
// Loading priority. Mods are loaded in order by ascending level of priority
// (the highest first). When 2 mods define the same loading priority the
// loading order is undefined.
extern "C" __declspec(dllexport) int getPriority() {
	// std::cout << "getPriority" << std::endl;
	return 0;
}

// Not yet implemented in the mod loader, subject to change
// SokuModLoader::IValue **getConfig();
// void freeConfig(SokuModLoader::IValue **v);
// bool commitConfig(SokuModLoader::IValue *);
// const char *getFailureReason();
// bool hasChainedHooks();
// void unHook();
// Author: 4148
// Copyright (c) 2014.
// All rights reserved.

#include "utils.h"

// definitions for util functions

// checks the result of a WINAPI function call for error
// if ERROR == RESULT && ERROR_EXIT == true, prints an error message and terminates application
// if ERROR_EXIT == false, returns true iff error occurred
// args: ERROR: error value; RESULT: actual value; FUNC_NAME: function name; ERROR_EXIT: exit flag
bool check_winapi_error(DWORD error, DWORD result, string func_name, bool error_exit) {
	if (error == result && error_exit) {
		cerr << "Error: " << func_name << " failed. Last error: " << GetLastError() << "." << endl;
		exit(1);
	}
	return (error == result);
}

// makes pages in the VAS of specified process read/writable; skips over free and reserved page regions
// args: PROCESS_HANDLE: handle returned by OpenProcess(); PROCESS_MODE: USER_MODE for user-mode process, KERNEL_MODE for kernel-mode process
void remove_permissions(HANDLE process_handle, PROCESS_MODE process_mode) {	
	// max and min addresses of VAS
	DWORD64 VAS_MAX, VAS_MIN;

	BOOL b = FALSE;
	// if 32-bit, B set to TRUE
	IsWow64Process(process_handle, &b);
	if (b == TRUE) {
		// in 32-bit, user space is lower 2 gibibytes
		if (PROCESS_MODE::USER_MODE == process_mode) {
			VAS_MIN = 0x0;
			VAS_MAX = 0x7FFFFFFF;
		// in 32-bit, system space is upper 2 gibibytes
		} else if (PROCESS_MODE::KERNEL_MODE == process_mode) {
			VAS_MIN = 0x80000000;
			VAS_MAX = 0xFFFFFFFF;
		}
	} else {
		// in 64-bit, user space is 8 tebibytes
		if (PROCESS_MODE::USER_MODE == process_mode) {
			VAS_MIN = 0x0;
			VAS_MAX = 0x7FFFFFFFFFF;
		// in 64-bit, system space is 248 tebibytes
		} else if (PROCESS_MODE::KERNEL_MODE == process_mode) {
			VAS_MIN = 0xFFFF080000000000;
			VAS_MAX = 0xFFFFFFFFFFFFFFFF;
		}
	}

	// address of page region
	DWORD64 address = VAS_MIN; 
	while (address <= VAS_MAX) {
		MEMORY_BASIC_INFORMATION memfo;
		// gets page region info
		if (check_winapi_error(0, VirtualQueryEx(process_handle, HMODULE(address), &memfo, sizeof(MEMORY_BASIC_INFORMATION)), "VirtualQueryEx()", false)) {
			// max address reached
			if (ERROR_INVALID_PARAMETER == GetLastError()) {
				return;
			} else {
				cerr << "Error: VirtualQueryEx() failed. Last error: " << GetLastError() << "." << endl;
				exit(1);
			}
		}

		// skip over free regions and reserved regions
		if (MEM_FREE == memfo.State || MEM_RESERVE == memfo.State) {
			address += memfo.RegionSize;
			continue;
		}
		DWORD temp;
		// sets page region to read/writable if not already
		if (((memfo.Protect & PAGE_NOACCESS) != 0) ||
			((memfo.Protect & PAGE_READONLY) != 0)) {
			// if data is shared, must use PAGE_WRITECOPY
			if (MEM_MAPPED == memfo.Type) {
				if (check_winapi_error(0, VirtualProtectEx(process_handle, memfo.BaseAddress, memfo.RegionSize, (memfo.Protect & 0xf00) | PAGE_WRITECOPY, &temp), "VirtualProtectEx()", false)) {
					if (ERROR_INVALID_PARAMETER == GetLastError()) {
						// do nothing. this is readonly data.
					} else {
						cerr << "Error: VirtualProtectEx() failed. Last error: " << GetLastError() << "." << endl;
						exit(1);
					} 
				}
			} else {
				check_winapi_error(0, VirtualProtectEx(process_handle, memfo.BaseAddress, memfo.RegionSize, (memfo.Protect & 0xf00) | PAGE_READWRITE, &temp), "VirtualProtectEx()", false);
			}
		} else if (((memfo.Protect & PAGE_EXECUTE) != 0) ||
			((memfo.Protect & PAGE_EXECUTE_READWRITE) != 0)) {
			check_winapi_error(0, VirtualProtectEx(process_handle, memfo.BaseAddress, memfo.RegionSize, (memfo.Protect & 0xf00) | PAGE_EXECUTE_READWRITE, &temp), "VirtualProtectEx()", true);
		}
		// computes addr of next page region
		address += memfo.RegionSize;
	}
}

// converts a string to a hexadecimal HMODULE address
HMODULE to_hex(string s) {
	DWORD64 addr = 0;
	for (int i = 0; i < s.length(); i++) {
		addr = (addr * 16) + to_hex(s[i]);
	}
	return HMODULE(addr);
}

// converts a hex char to its corresponding DWORD64 (unsigned int) value
DWORD64 to_hex(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return 10 + (c - 'A');
	} else if (c >= 'a' && c <= 'f') {
		return 10 + (c - 'a');
	} else {
		cerr << "Error: to_hex(char) passed non-hex char." << endl;
		exit(1);
	}
}

// converts a string to an integer, if possible
// the string should only contain integers; if it contains characters, an error is thrown
int to_int(string s) {
	int rtn = 0;
	int negation = 1;
	for (int i = 0; i < s.length(); i++) {
		if ((s[i] >= '0' && s[i] <= '9')) {
			rtn = (rtn * 10) + (s[i] - '0');
		} else if (i == 0 && s[i] == '-') {
			negation *= -1;
		} else {
			cerr << "Error: to_int() passed non-integer string." << endl;
			exit(1);
		}
	}
	return rtn * negation;
}

// prints a formatted string with a max line width, separated by delimiter delim (which is appended to newline)
void print_format(string s, unsigned int width, string delim) {
	unsigned int start = 0;
	unsigned int increment = width;
	while (s.length() > start) {
		if ((start + width) > s.length()) {
			cout << s.substr(start, s.length() - start) << endl << delim;
			break;
		} else {
			increment = width;
			while (s.at(start+increment-1) != ' ') { // searches for nearest space at the back
				if (increment <= (width/2)) { // arbitrary cutoff
					increment = width;
					break;
				}
				increment--;
			}
			cout << s.substr(start, increment) << endl << delim;
		}
		start += increment;
	}	
}

// returns the base address of an .exe given a process
// args: PATH: .exe's file path; PROCESS_HANDLE: handle returned by OpenProcess()
HMODULE get_base_address(HANDLE process_handle, wstring path) {
	HMODULE rtn = NULL;
	DWORD hmarr_size = 10;
	// holds array of modules output by EnumProcessModules()
	HMODULE* hmarr = new HMODULE[hmarr_size];
	// bytes needed
	DWORD needed = 0;
	// get array of modules associated with the target process; use extended version to enum 64-bit/32-bit processes
	int result = EnumProcessModulesEx(process_handle, hmarr, hmarr_size, &needed, LIST_MODULES_ALL);
	if (needed > hmarr_size) {
		delete[] hmarr;
		hmarr_size = needed/sizeof(HMODULE);
		hmarr = new HMODULE[hmarr_size];
		result = EnumProcessModulesEx(process_handle, hmarr, needed, &needed, LIST_MODULES_ALL);
	}
	if (0 == result) {
		cerr << "Error: EnumProcessModules() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
		cerr << "Variables: needed: " << needed << "." << endl;
		exit(1);
	}

	wchar_t* module_path = new wchar_t[path.length()+1];
	// find module of specified path
	for (int i = 0; i < (needed/sizeof(HMODULE)); i++) {
		GetModuleFileNameEx(process_handle, hmarr[i], module_path, (DWORD) path.length());
		if (to_upper(basename(path)) == to_upper(basename(module_path))) {
			rtn = hmarr[i];
			break;
		}
	}
	
	delete[] module_path;
	delete[] hmarr;
	return rtn;
}

// converts wstring to uppercase
wstring to_upper(wstring ws) {
	wchar_t* warr = new wchar_t[ws.length()+1];
	for (int i = 0; i < ws.length()+1; i++) {
		warr[i] = towupper(ws[i]);
	}
	wstring temp(warr);
	delete[] warr;
	return temp;
}

// returns a wstring representation of string s
wstring to_wstring(string s) {
	wchar_t* warr = new wchar_t[s.length()+1];
	mbstowcs(warr, s.c_str(), s.length()+1);
	wstring rtn(warr);
	delete[] warr;
	return rtn;
}

// returns the file name of a path
// works for both '\\' and '/' delimiters
string basename(string path) {
	size_t cutoff = path.length()-2;
	while (cutoff >= 0 && (path.at(cutoff) != '\\' && path.at(cutoff) != '/')) { cutoff--; }
	if (cutoff < 0) { return path; }
	return path.substr(cutoff+1);
}
// wide string version
wstring basename(wstring path) {
	size_t cutoff = path.length()-2;
	while (cutoff >= 0 && (path.at(cutoff) != '\\' && path.at(cutoff) != '/')) { cutoff--; }
	if (cutoff < 0) { return path; }
	return path.substr(cutoff+1);
}

// Author: 4148
// Copyright (c) 2014.
// All rights reserved.

#include "utils.h"

// definition for helper functions

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
// path is the .exe's file path, process_handle is the value returned by OpenProcess()
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

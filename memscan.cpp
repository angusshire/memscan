#include <iostream>
#include <string>
#include <vector>
#include <ctime>
using namespace std;
#include <windows.h>
#include <Psapi.h>

// Author: 4148
// Copyright (c) 2014.
// All rights reserved.

// arises from need to store the matching value, size of value, and associated address
typedef struct Match {
	HMODULE address;
	DWORD64 value;
	size_t size;
} Match;

// function prototypes
string basename(string path);
wstring basename(wstring path);
wstring to_wstring(string s);
wstring to_upper(wstring ws);
HMODULE get_base_address(HANDLE process_handle, wstring path);
void process_memblock(DWORD64 memblock, vector<Match*>& matches, DWORD64, const bool VALUE_SPECIFIED = false, const DWORD64 value = NULL);
void delete_matches(const vector<Match*>&);

// returns the base address of a given process
// path is the .exe's file path, process_handle is the value returned by OpenProcess()
HMODULE get_base_address(HANDLE process_handle, wstring path) {
	HMODULE rtn = NULL;
	DWORD hmarr_size = 10;
	// holds array of modules output by EnumProcessModules()
	HMODULE* hmarr = new HMODULE[hmarr_size];
	// bytes needed
	DWORD needed = 0;
	// get array of modules associated with the target process; use extended version to enum 64-bit processes
	int result = EnumProcessModulesEx(process_handle, hmarr, hmarr_size, &needed, LIST_MODULES_ALL);
	if (needed > hmarr_size) {
		delete[] hmarr;
		hmarr = new HMODULE[needed];
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
	return rtn; // return by value
}

// returns the file name of a path
// works for both '\\' and '/' delimiters
string basename(string path) {
	int cutoff = path.length()-2; // -2 instead of -1 just in case last char is '/'
	while (cutoff >= 0 && (path.at(cutoff) != '\\' && path.at(cutoff) != '/')) { cutoff--; }
	if (cutoff < 0) { return path; }
	return path.substr(cutoff+1);
}
// wide string version
wstring basename(wstring path) {
	int cutoff = path.length()-2; // -2 instead of -1 just in case last char is '/'
	while (cutoff >= 0 && (path.at(cutoff) != '\\' && path.at(cutoff) != '/')) { cutoff--; }
	if (cutoff < 0) { return path; }
	return path.substr(cutoff+1);
}

// memory scanner for 64-bit Windows
// (1) initialize process image name and value to be scanned (if specified) based on input
// (2) get handle to the first instance of the process with specified image name
// (3) scan process for value, if specified

// (2) scan specified process for value, keeping track of all the addresses in which it occurs
// (3) if -m flag is used, monitor those addresses for changes
// (4) 
// (2) scans process for specified value and/or changes
// freeze value by writing with new value, using timer to write memory in every time period
int main(int argc, char* argv[]) {
	BOOL b = false;
	// determines whether current process is running under WOW64.
	// Should always be false, because cannot read memory from a 64-bit module on a 32-bit process (cannot create selector to all addresses on 64-bit, unlike 16-bit to 32-bit)
	IsWow64Process(GetCurrentProcess(), &b);
	// EnumProcessModules() fails when a 32-bit process tries to enum 64-bit modules, so changed active solution platform to x64
	if (b == true) {
		cerr << "Error: Current process is running under WOW64." << endl;
		exit(1);
	}
	
	clock_t beg = clock();
	//if (argc != 2) {
		cout << "Usage: memscan processImageName [-v value] [-m] [-bwdq]" << endl;
		cout << "Scans specified process for memory addresses. Prints first 100 matches." << endl;
		cout << "\t-v value: value to match addresses against." << endl;
		cout << "\t-m: monitor matching addresses for changes." << endl;
		cout << "\t-bwdq: specifies combination of container sizes to match addresses against." << endl;
		cout << "\t-b is byte, -w is word (16 bits), -d is doubleword, -q is quadword." << endl;
		cout << "\t Default matches only doublewords." << endl;
	//}

	// name of process to be scanned
	string process_image_name("minesweeper");
	if (process_image_name.find(".exe") == string::npos) { process_image_name.append(".exe"); } // appends '.exe' if extension not there
	// flag for whether value is specified
	const bool VALUE_SPECIFIED = false;
	// flag for whether sizes to read is specified
	const bool SIZE_SPECIFIED = false;
	// value to be scanned for
	int value;

	// number of processses 	
	size_t num_processes = 100;
	// contains all process ids
	DWORD* process_ids = new DWORD[num_processes];
	DWORD bytes_returned = 0;
	// loop retrieves all process ids into process_ids
	while (true) {
		if (0 == EnumProcesses(process_ids, num_processes*4, &bytes_returned)) {
			// when used inside the function, __FILE__ is the path of file in which function was defined, not where it was called
			cerr << "Error: EnumProcesses() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
			exit(1);
		}
		if (bytes_returned < (num_processes*4)) { break; }
		num_processes *= 2;
		delete[] process_ids;
		process_ids = new DWORD[num_processes];
	}
	num_processes = bytes_returned / 4;

	// contains handle of current process
	HANDLE process_handle;
	// virtual base address .exe process; in Windows NT, base address is module's handle; HMODULE = HINSTANCE, but were different things in 16-bit Windows
	HMODULE base_address;
	// loops gets handle of process with specified image name
	for (int i = 0; i < num_processes; i++) {
		if (process_ids[i] == 0) { continue; } // ignore system process
		// gets handle to process from process id
		process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, process_ids[i]);
		if (NULL == process_handle) {
			if (ERROR_ACCESS_DENIED == GetLastError()) { continue; } // ignore idle processes and CSRSS processes
			cerr << "Error: OpenProcess() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
			exit(1);
		}

		size_t temp_size = MAX_PATH;
		// process name
		wchar_t* temp_process_name = new wchar_t[temp_size];
		// loop gets process name from process handle
		while (true) {
			if (0 == GetProcessImageFileName(process_handle, temp_process_name, temp_size)) {
				cerr << "Error: GetProcessImageFileName() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
				exit(1);
			} else if (wcslen(temp_process_name) == (temp_size-1)) {
				temp_size *= 2;
				delete[] temp_process_name;
				temp_process_name = new wchar_t[temp_size];
			} else {
				break;
			}
		}
		// case insensitive name comparison
		if (to_upper(to_wstring(process_image_name)) == to_upper(basename(temp_process_name))) {
			// if process name matches specified image name, get base address, then break (process handle will be closed later)
			base_address = get_base_address(process_handle, temp_process_name);
			if (NULL == base_address) {
				cerr << "Error: get_base_address() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
				exit(1);
			}
			delete[] temp_process_name;
			break;
		} else {
			// if process name does not match specified image name, close handle, and continue
			delete[] temp_process_name;
			CloseHandle(process_handle);
			process_handle = NULL;
		}
	}

	if (NULL == process_handle) {
		cerr << "Error: Unable to find process with image name " << process_image_name << "." << endl;
		exit(1);
	} else {
		// specified sizes of memory block to read
		vector<SIZE_T> sizes;
		if (SIZE_SPECIFIED) {
			
		} else { sizes.push_back(4); }

		// initial base address (for debugging purposes)
		HMODULE initial_address = base_address;
		// how many times we've looped (for debugging purposes)
		int iteration = 0;
		// vector of matching values
		vector<Match*> matches;
		while (true) {
			// bytes retrieved
			SIZE_T bytes_transferred = 0;
			// num DWORD64s to read; optimal is one pass (apparenty 120,000 for MineSweeper.exe is 2 times faster than 80000, probably because it requires only a single iteration)
			const size_t num_d64 = 120000;
			cout << sizeof(size_t) << endl;
			// num bytes to read
			SIZE_T block_size = num_d64*sizeof(DWORD64);
			DWORD64 memblock[num_d64];
			// increment for base_address, in sizeof(int) units
			size_t increment = block_size / sizeof(int);
			// itc, pointer means variable that contains memory address rather than the memory address itself1
			if (0 == ReadProcessMemory(process_handle, base_address, memblock, block_size, &bytes_transferred)) {
				if (ERROR_PARTIAL_COPY == GetLastError()) {
					// readjusts block_size and num_d64 accordingly, by halving and doubling until the correct number of bytes is reached
					while (true) {
						do {
							num_d64 /= 2;
							block_size = num_d64*sizeof(DWORD64);
						} while (0 == ReadProcessMemory(process_handle, base_address, memblock, block_size, &bytes_returned));
						if (bytes_transferred == block_size) {
							num_d64 *= 2; 
						} else {
							break;
						}
					}
				} else {	
					cout << "Warning: ReadProcessMemory() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
					cout << "Variables: bytes_transferred: " << bytes_transferred << ", block_size: " << block_size << ", iteration: " << iteration << << ", base_address: " << base_address << ", initial_address: " << initial_address << "." << endl;
					break;
				}
			} else {
			
				base_address += increment; // pointer arithmetic in C++: unit of increment is sizeof thing pointed to
			}


//		
//		}
			iteration++;
		}
		delete_matches(matches);
	}
		
	
	delete[] process_ids;
	CloseHandle(process_handle);

	clock_t end = clock();
	double diff = double(end - beg) / CLOCKS_PER_SEC;
	cout << "Execution took " << diff << " seconds." << endl;
}

void freeze(HMODULE address, int value) {
}




void process_memblock(SIZE_T sizes, DWORD64* memblock, vector<Match*>& matches, DWORD64, HMODULE base_address, const bool VALUE_SPECIFIED = false, const DWORD64 value = NULL);
// processes the specified memory block by finding the matches to the value (if specified) and then putting them into the matches array
// arguments: sizes: which sizes to read from memblock, memblock: array of read memory values, base_address: address from which memblock[0] was read, 
// [arguments con't] base_address: base address of the last meblock read, VALUE_SPECIFIED: whether value is specified, value: if VALUE_SPECIFIED == true, then value to search for 
void process_memblock(SIZE_T sizes, DWORD64* memblock, DWORD64 memblock_size, vector<Match*>& matches, HMODULE base_address, const bool VALUE_SPECIFIED, const DWORD64 value) {
	for (int i = 0; i < memblock_size; i++) {
		for (SIZE_T size : sizes) {
			if (value == memblock[i] || !VALUE_SPECIFIED) {
				Match* match = new Match;
				match->address = base_address + i; 
				match->value = value;
				match->size = size;
				matches.push_back(match);		
			}
		}
	}
}

// deletes specified matches
void delete_matches(const vector<Match*>& matches) {
	for (Match* m : matches) {
		delete matches;
	}
}

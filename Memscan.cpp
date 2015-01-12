// implementation file for Memscan.h

#include "Memscan.h"

// constructor sets instance vars
// args: pin: name of process to be scanned
Memscan::Memscan(string pin, PROCESS_MODE process_mode) {
	if (pin.find(".exe") == string::npos) { pin.append(".exe"); } // appends '.exe' if extension not there
	processImageName = pin;
	// sets SIZE_SPECIFIED flag to false
	vector<SIZE_T> s;
	s.push_back(4); // default scan size is DWORD (4 bytes)
	setSizeSpecified(false, s);

	// sets BASEADDRESS and PROCESSHANDLE
	if (processImageName.length() == 0) {
		cerr << "Error: processImageName must be set." << endl;
		exit(1);
	}

	// number of processses
	DWORD num_processes = 100;
	// contains all process ids
	DWORD* process_ids = new DWORD[num_processes];
	DWORD bytes_returned = 0;
	// loop retrieves all process ids into process_ids
	while (true) {
		if (0 == EnumProcesses(process_ids, num_processes*sizeof(DWORD), &bytes_returned)) {
			cerr << "Error: EnumProcesses() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
			exit(1);
		}
		if (bytes_returned < (num_processes*sizeof(DWORD))) { break; }
		num_processes *= 2;
		delete[] process_ids;
		process_ids = new DWORD[num_processes];
	}
	num_processes = bytes_returned / 4;

	// contains handle of target process
	HANDLE process_handle;
	// virtual base address of target process (where .exe map begins)
	HMODULE base_address;
	// loops gets handle of process with specified image name
	for (int i = 0; i < num_processes; i++) {
		if (0 == process_ids[i]) { continue; } // ignore system process
		// gets handle to process from process id
		process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_ids[i]);
		if (NULL == process_handle) {
			if (ERROR_ACCESS_DENIED == GetLastError()) { continue; } // ignore idle processes and CSRSS processes
			cerr << "Error: OpenProcess() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
			exit(1);
		}

		DWORD temp_size = MAX_PATH;
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
		if (to_upper(to_wstring(processImageName)) == to_upper(basename(temp_process_name))) {
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

	delete[] process_ids;

	if (NULL == process_handle) {
		cerr << "Error: Unable to find process with image name " << processImageName << "." << endl;
		exit(1);
	} else {
		processHandle = process_handle;
		baseAddress = base_address;
	}

	// default SCANATTRIBUTE is NONE
	scanAttribute = SCAN_ATTRIBUTE::NONE;
	// first scan
	RESCAN = false;

	// sets mode
	processMode = process_mode;
	// removes permissions from pages of process being scanned
	remove_permissions(processHandle, processMode);
	// sets VAS_MIN, VAS_MAX
	setVasBounds();
}

// sets VAS_MIN and VAS_MAX
void Memscan::setVasBounds() {
	BOOL b = FALSE;
	// if 32-bit, B set to TRUE
	IsWow64Process(processHandle, &b);
	if (b == TRUE) {
		// in 32-bit, user space is lower 2 gibibytes
		if (PROCESS_MODE::USER_MODE == processMode) {
			VAS_MIN = 0x0;
			VAS_MAX = 0x7FFFFFFF;
		// in 32-bit, system space is upper 2 gibibytes
		} else if (PROCESS_MODE::KERNEL_MODE == processMode) {
			VAS_MIN = 0x80000000;
			VAS_MAX = 0xFFFFFFFF;
		}
	} else {
		// in 64-bit, user space is 8 tebibytes
		if (PROCESS_MODE::USER_MODE == processMode) {
			VAS_MIN = 0x0;
			VAS_MAX = 0x7FFFFFFFFFF;
		// in 64-bit, system space is 248 tebibytes
		} else if (PROCESS_MODE::KERNEL_MODE == processMode) {
			VAS_MIN = 0xFFFF080000000000;
			VAS_MAX = 0xFFFFFFFFFFFFFFFF;
		}
	}
}

// frees memory and removes everything in MATCHES
void Memscan::deleteMatches() {
	while (!matches.empty()) {
		delete matches.back();
		matches.pop_back();
	}
}

// setter for SIZE_SPECIFIED flag
// args: b: bool to set flag to; s: vector of sizes to read from memory
void Memscan::setSizeSpecified(bool b, vector<SIZE_T>& s) {
	SIZE_SPECIFIED = b;
	for (SIZE_T size : s) {
		if (size != 1 && size != 2 && size != 4 && size != 8) {
			cout << "Error: size must be 1 (byte), 2 (word), 4 (dword), or 8 (quadword)." << endl;
			exit(1);
		}
	}
	sizes = s;
}

// prints out specified matches formatted by their Match type
// args: limit: number of entries to print IN TOTAL (default is 100)
void Memscan::printMatches(size_t limit) {
	cout << "Printing first " << limit << " matches (" << matches.size() << " matches total)... FORMAT: [base address: offset: value: float]" << endl;
	ostringstream b, w, d, q;
	size_t num_entries = 0;
	for (Match* m : matches) {
		if (num_entries >= limit) {
			break;
		}
		if (1 == m->size) { // size is BYTE
			b << hex << uppercase << DWORD64(m->address) << nouppercase << dec << ": " << m->offset << ": " << m->value << ": " << parse_float(m->value, m->size) << endl;
		} else if (2 == m->size) { // size is WORD
			w << hex << uppercase << DWORD64(m->address) << nouppercase << dec << ": " << m->offset << ": " << m->value << ": " << parse_float(m->value, m->size) << endl;
		} else if (4 == m->size) { // size is DWORD
			d << hex << uppercase << DWORD64(m->address) << nouppercase << dec << ": " << m->offset << ": " << m->value << ": " << parse_float(m->value, m->size) << endl;
		} else if (8 == m->size) { // size is QUADWORD
			q << hex << uppercase << DWORD64(m->address) << nouppercase << dec << ": " << m->offset << ": " << m->value << ": " << parse_float(m->value, m->size) << endl;
		} else {
			cout << "Error: size not specified." << endl;
			exit(1);
		}
		num_entries++;
	}
	if (b.str().length() != 0) {
		cout << "BYTE" << endl;
		cout << b.str();
	}
	if (w.str().length() != 0) {
		cout << "WORD" << endl;
		cout << w.str();
	}
	if (d.str().length() != 0) {
		cout << "DWORD" << endl;
		cout << d.str();
	}
	if (q.str().length() != 0) {
		cout << "QUADWORD" << endl;
		cout << q.str();
	}
}

// adds a Match* to MATCHES
// args: BASE_ADDRESS: base address of Match; VALUE: value found at address BASE_ADDRESS+(SIZE*OFFSET),
// [args con't] SIZE: size of VALUE, in bytes; OFFSET: offset to BASE_ADDRESS where VALUE is found, in terms of SIZE
void Memscan::addMatch(HMODULE base_address, DWORD64 value, size_t size, size_t offset) {
	Match* match = new Match;
	match->address = base_address;
	match->value = value;
	match->size = size;
	match->offset = offset;
	if (matches.max_size() == matches.size()) {
		cout << "Warning: Maximum size reached for MATCHES." << endl;
	} else {
		matches.push_back(match);
	}
}

// processes the MEMBLOCK by finding matches to SCANVALUE (if specified) of specified size; adds matches to MATCHES
// args: MEMBLOCK: array of read memory values; MEMBLOCK_SIZE: size of memory block; BASE_ADDRESS: address where first value in MEMBLOCK was read
void Memscan::processMemblock(DWORD64* memblock, DWORD64 memblock_size, HMODULE base_address) {
	for (int i = 0; i < memblock_size; i++) {
		DWORD64 value = memblock[i];
		DWORD64 initial = value;
		HMODULE matchBaseAddress = base_address + (i * 2); // +(i*2) because HMODULE values are incremented in sizeof(int) units; DWORD64 = 2 * sizeof(int)
		for (SIZE_T size : sizes) {
			DWORD64 mask = 0;
			if (size == 8) { // necessary because left shift is undefined if right operand equals to number of bits in left operand
				mask = 0xffffffffffffffff;
			} else {
				mask = ~(0xffffffffffffffff << (size * 8)); // masks last SIZE*8 bits
			}
			// Windows NT is little-endian
			for (int i = 0; i < (sizeof(DWORD64)/size); i++) {
				if ((SCAN_ATTRIBUTE::NONE == scanAttribute) || ((SCAN_ATTRIBUTE::VALUE == scanAttribute) && ((value & mask) == scanValue))) {
					addMatch(matchBaseAddress, (value & mask), size, i);
				}
				if (size < 8) {
					value >>= (size * 8); // shifts right by SIZE*8 bits
				}
			}
			value = initial;
		}
	}
}

// scans memory according to SCANATTRIBUTE, and adds matches to MATCHES
void Memscan::scan() {
	// rescans MATCHES with specified attributes if first scan already done
	if (RESCAN) {
		rescan();
		return;
	}
	// empties MATCHES and FROZEN if first scan
	if (!matches.empty()) { deleteMatches(); deleteFrozen(); }
	// local base address (so member variable is not changed)
	HMODULE base_address = HMODULE(VAS_MIN);
	// how many times we've looped (for debugging purposes)
	int iteration = 0;
	// bytes retrieved
	SIZE_T bytes_transferred = 0;
	// num DWORD64s to read;
	SIZE_T num_d64 = 100000;
	// num bytes to read
	SIZE_T block_size = num_d64*sizeof(DWORD64);
	// array of DWORD64s to copy memory values into
	DWORD64* memblock = new DWORD64[num_d64];
	// increment for base_address, in sizeof(int) units
	SIZE_T increment = block_size / sizeof(int);
	while (base_address <= HMODULE(VAS_MAX)) {
		MEMORY_BASIC_INFORMATION memfo;
		// gets page region info
		if (check_winapi_error(0, VirtualQueryEx(processHandle, base_address, &memfo, sizeof(MEMORY_BASIC_INFORMATION)), "VirtualQueryEx()", false)) {
			// max address reached
			if (ERROR_INVALID_PARAMETER == GetLastError()) {
				break;
			} else {
				cerr << "Error: VirtualQueryEx() failed. Last error: " << GetLastError() << "." << endl;
				exit(1);
			}
		}
		// skip over free regions and reserved regions
		if (MEM_FREE == memfo.State || MEM_RESERVE == memfo.State) {
			// resets num_d64 and associated vars
			num_d64 = 100000;
			block_size = num_d64*sizeof(DWORD64);
			increment = block_size / sizeof(int);
			base_address += memfo.RegionSize;
			continue;
		}

		if (0 == ReadProcessMemory(processHandle, base_address, memblock, block_size, &bytes_transferred)) {
			if (ERROR_PARTIAL_COPY == GetLastError()) {
				bool FIRST = true;
				// readjusts block_size and num_d64 accordingly, by halving and doubling until the correct number of bytes is reached
				while (1 <= num_d64) {
					while ((1 <= num_d64) && (FIRST || (0 == ReadProcessMemory(processHandle, base_address, memblock, block_size, &bytes_transferred)))) {
						num_d64 /= 2; // no need to ceil, since once it reaches 1 it will read the rest
						block_size = num_d64*sizeof(DWORD64);
						increment = block_size / sizeof(int);
						FIRST = false;
					}
					processMemblock(memblock, num_d64, base_address);
					base_address += increment;
				}
			} else {
				cout << "Warning: ReadProcessMemory() failed in " << basename(__FILE__) << ":" << __LINE__ << ". Last error: " << GetLastError() << "." << endl;
				cout << "Variables: bytes_transferred: " << bytes_transferred << ", block_size: " << block_size << ", iteration: " << iteration << endl;
				cout << "Variables [con't]: base_address: " << base_address << endl;
				break;
			}
		} else {
			processMemblock(memblock, num_d64, base_address);
			base_address += increment;
			iteration++;
		}
	}
	delete[] memblock;
	RESCAN = true;
}

// rescans MATCHES with specified attribute
void Memscan::rescan() {
	// leave original matches unmodified if attribute not specified
	if (SCAN_ATTRIBUTE::NONE == scanAttribute) {
		return;
	} else {
		matches.erase(remove_if(matches.begin(), matches.end(), [this](Match* m)->bool{
			SIZE_T bytes_transferred;
			DWORD64 value = 0;
			DWORD64 address = DWORD64(m->address) + DWORD64((m->size) * (m->offset));
			if (0 == ReadProcessMemory(processHandle, (HMODULE) address, &value, m->size, &bytes_transferred)) {
				cout << "Warning: ReadProcessMemory() failed in rescan()." << endl;
				return false;
			}

			// if attribute condition is satisifed, leave Match; otherwise, erase it
			if (((scanAttribute == SCAN_ATTRIBUTE::CHANGED) && m->value != value) ||
				((scanAttribute == SCAN_ATTRIBUTE::UNCHANGED) && m->value == value) ||
				((scanAttribute == SCAN_ATTRIBUTE::INCREASED) && m->value < value) ||
				((scanAttribute == SCAN_ATTRIBUTE::DECREASED) && m->value > value) ||
				((scanAttribute == SCAN_ATTRIBUTE::VALUE) && value == scanValue) ||
				((scanAttribute == SCAN_ATTRIBUTE::FLOAT_INCREASED) && (parse_float(m->value, m->size) < parse_float(value, m->size))) ||
				((scanAttribute == SCAN_ATTRIBUTE::FLOAT_DECREASED) && (parse_float(m->value, m->size) > parse_float(value, m->size)))) {
				m->value = value;
				return false;
			} else {
				delete m;
				return true;
			}
		}), matches.end());
	}
}

// sets SCANATTRIBUTE to specified attribute
// args: RA: value to set SCANATTRIBUTE to; V: value to set SCANVALUE to
void Memscan::setScanAttribute(SCAN_ATTRIBUTE ra, DWORD64 v) {
	scanAttribute = ra;
	if (SCAN_ATTRIBUTE::VALUE == scanAttribute) {
		scanValue = v;
	}
}

// begins a new scan for the process by deleting all matches, setting RESCAN to false, reinitializing SIZES, and resetting SCANATTRIBUTE
void Memscan::newscan(vector<SIZE_T>& s) {
	RESCAN = false;
	deleteMatches();
	deleteFrozen();
	setSizeSpecified(true, s);
	setScanAttribute(SCAN_ATTRIBUTE::NONE);
}

// adds a Match* to FROZEN
// args: BASE_ADDRESS: base address of Match; VALUE: value to be written at address BASE_ADDRESS+(SIZE*OFFSET),
// [args con't] SIZE: size of VALUE, in bytes; OFFSET: offset to BASE_ADDRESS where VALUE is to be written, in terms of SIZE
void Memscan::addFrozen(HMODULE base_address, DWORD64 value, size_t size, size_t offset) {
	Match* match = new Match;
	match->address = base_address;
	match->value = value;
	match->size = size;
	match->offset = offset;
	if (frozen.max_size() == frozen.size()) {
		cout << "Warning: Maximum size reached for FROZEN." << endl;
	} else {
		frozen.push_back(match);
	}
}

// frees memory and removes everything in FROZEN
void Memscan::deleteFrozen() {
	while (!frozen.empty()) {
		delete frozen.back();
		frozen.pop_back();
	}
}

// freezes Matches* in FROZEN at 100ms intervals
// this method should be called in a secondary thread
void Memscan::freeze() {
	while (true) {
		for (Match* m : frozen) {
			DWORD64 address = DWORD64(m->address) + (m->offset * m->size);
			DWORD64 write_val = m->value;
			SIZE_T bytes_transferred = 0;
			if (0 == WriteProcessMemory(processHandle, HMODULE(address), &write_val, SIZE_T(m->size), &bytes_transferred)) {
				if (ERROR_NOACCESS == GetLastError()) {
					MEMORY_BASIC_INFORMATION mem;
					VirtualQueryEx(processHandle, HMODULE(address), &mem, sizeof(MEMORY_BASIC_INFORMATION));
					cout << hex << mem.AllocationProtect << endl;
					cout << mem.State << endl;
					cout << mem.Protect << endl;
					cout << mem.Type << dec << endl;

					cout << "WriteProcessMemory() failed with ERROR_NOACCESS error with address " << hex << address << dec << "." << endl;
				} else {
					cout << "WriteProcessMemory() failed with address " << hex << address << dec << " and error " << GetLastError() << "." << endl;
				}
			}
		}
		Sleep(100);
	}
}

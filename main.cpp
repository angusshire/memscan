#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <cassert>
#include <limits>
using namespace std;
#define NOMINMAX // removes the macro max() defined in windows.h so doesn't conflict with <limits>
#include "Memscan.h"
#include "process.h"
//#define NDEBUG

// application helper functions
void usage_message();
bool valid_sizes(const char* sizes, vector<SIZE_T>& s);
void run_tests();

// memory scanner for 64-bit Windows
int main(int argc, char* argv[]) {
// runs tests and times first scan if in debugging mode
#ifndef NDEBUG
	run_tests();
	clock_t beg = clock();
#endif
	// determines whether current process is running under WOW64.
	// should always be false, because cannot read memory from a 64-bit module in a 32-bit process (cannot create selector for all addresses on 64-bit, unlike for 32-bit in 16-bit, because 32-bit Windows abandoned selectors)
	BOOL b = FALSE;
	IsWow64Process(GetCurrentProcess(), &b);
	if (b == TRUE) {
		cerr << "Error: Current process is running under WOW64." << endl;
		exit(1);
	}

	// scan process
	static Memscan* memscan;
	// vector of sizes to read from memory
	vector<SIZE_T> sizes;
	// true iff size is specified
	bool SIZE_SPECIFIED = false;
	// true iff scan value is specified
	bool VALUE_SPECIFIED = false;
	// scan value
	DWORD64 SCAN_VALUE;
	// type of process being scanned; for now, only user-mode processes are supported
	PROCESS_MODE process_mode = PROCESS_MODE::USER_MODE;
	// argument range
	const int MAX_ARGS = 5, MIN_ARGS = 2;
	// parses command line arguments
	if (argc >= MIN_ARGS && argc <= MAX_ARGS) {
		for (int i = MIN_ARGS; i < argc; i++) {
			if (string(argv[i]) == "-v") {
				if ((i+1) < argc) {
					i++;
					VALUE_SPECIFIED = true;
					SCAN_VALUE = (DWORD64) to_int(argv[i]);
				} else {
					usage_message();
					return 0;
				}
			} else if (valid_sizes(argv[i], sizes)) {
				SIZE_SPECIFIED = true;
			} else {
				usage_message();
				return 0;
			}
		}
		memscan = new Memscan(argv[1], process_mode);
		if (SIZE_SPECIFIED)
			memscan->setSizeSpecified(SIZE_SPECIFIED, sizes);
		if (VALUE_SPECIFIED)
			memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::VALUE, SCAN_VALUE);

		// first scan
		cout << "Scanning..." << endl;
		memscan->scan();
		cout << "Scan complete." << endl;

		#ifndef NDEBUG
			clock_t end = clock();
			double diff = double(end - beg) / CLOCKS_PER_SEC;
			cout << "First scan took " << diff << " seconds." << endl;
		#endif

		// begins secondary thread for freezing values
		_beginthread([](void* v)->void{
			memscan->freeze();
		}, 0, 0);

		// user-input loop
		string input;
		do {
			cout << "'print': print matches." << endl;
			cout << "'new': begin new scan for specified memory units." << endl;
			cout << "'criteria': specify scan critera." << endl;
			cout << "'scan': rescan current matches with critera." << endl;
			cout << "'freeze': freeze an address with a value." << endl;
			cout << "'exit': exit the program." << endl;
			getline(cin, input);
			if (input == "exit") {
				cout << "Terminating program..." << endl;
				break;
			} else if (input == "new") {
				cout << "Enter memory units in the form [-bwdq]." << endl;
				string sizes_input;
				getline(cin, sizes_input);
				if (valid_sizes(sizes_input.c_str(), sizes)) {
					cout << "Sizes was set." << endl;
					cout << "Beginning new scan for sizes " << sizes_input << "..." << endl;
					memscan->newscan(sizes);
					memscan->scan();
					cout << "Scan complete." << endl;
				} else {
					cout << "Invalid sizes. Sizes was not set." << endl;
				}
			} else if (input == "criteria") {
				string inner_input;
				do {
					cout << "'value': scan matches for specified value." << endl;
					cout << "'changed': scan matches for changes." << endl;
					cout << "'unchanged': scan matches for unchanged values." << endl;
					cout << "'increased': scan matches for increased values." << endl;
					cout << "'decreased': scan matches for decreased values." << endl;
					cout << "'exit': return to main input loop." << endl;
					cout << "'float i': scan matches for increased floating-point values." << endl;
					cout << "'float d': scan matches for decreased floating-point values." << endl;
					getline(cin, inner_input);
					if (inner_input == "exit") {
						cout << "Returning to main input loop..." << endl;
						break;
					} else if (inner_input == "value") {
						cout << "Please enter value to scan for in matches (must be an integer)." << endl;
						DWORD64 value;
						cin >> value;
						cin.ignore(std::numeric_limits<streamsize>::max(), '\n');
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::VALUE, value);
						cout << "Value was set." << endl;
						cout << "Rescanning for value " << value << "..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "changed") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::CHANGED);
						cout << "Rescanning for changed values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "unchanged") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::UNCHANGED);
						cout << "Rescanning for unchanged values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "increased") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::INCREASED);
						cout << "Rescanning for increased values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "decreased") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::DECREASED);
						cout << "Rescanning for decreased values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "float i") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::FLOAT_INCREASED);
						cout << "Rescanning for float increased values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else if (inner_input == "float d") {
						memscan->setScanAttribute(Memscan::SCAN_ATTRIBUTE::FLOAT_DECREASED);
						cout << "Rescanning for float decreased values..." << endl;
						memscan->scan();
						cout << "Scan complete." << endl;
					} else {
						cout << "Invalid input. Please try again." << endl;
						continue;
					}
				} while (true);
			} else if (input == "freeze") {
				cout << "Base address (in hex) to write?" << endl;
				string base;
				getline(cin, base);
				HMODULE addr = to_hex(base);

				cout << "Offset to base address, in bytes?" << endl;
				int offset = 0;
				if (cin >> offset) {
					if (offset >= 8 || offset < 0) { cout << "Invalid offset." << endl; continue; }
					cin.ignore(std::numeric_limits<streamsize>::max(), '\n'); }
				else { cout << "Invalid offset." << endl; continue; }

				cout << "Write with what integer value?" << endl;
				int freeze_val = 0;
				if (cin >> freeze_val) { cin.ignore(std::numeric_limits<streamsize>::max(), '\n'); }
				else { cout << "Invalid freeze value." << endl; continue; }

				cout << "Size of value, in bytes?" << endl;
				DWORD64 freeze_size = 0;
				if (cin >> freeze_size) {
					cin.ignore(std::numeric_limits<streamsize>::max(), '\n'); }
				else { cout << "Invalid freeze size." << endl; continue; }

				memscan->addFrozen(addr, freeze_val, freeze_size, offset);
				cout << "Address " << addr << " will be frozen with value " << freeze_val << "." << endl;
				Sleep(500);
			} else if (input == "print") {
				memscan->printMatches();
			} else if (input == "scan") {
				cout << "Rescanning..." << endl;
				memscan->scan();
				cout << "Scan complete." << endl;
			} else {
				cout << "Invalid input. Please try again." << endl;
				continue;
			}
		} while (true);
	} else {
		usage_message();
		return 0;
	}

	delete memscan;
	return 0;
}

// prints usage message for memscan app
void usage_message() {
	print_format("Usage: memscan processImageName [-v value] [-bwdq]", 80, "");
	print_format("memscan scans specified user-mode process for memory addresses and prints matches.", 80, "\t");
	print_format("-v value: value to match addresses against.", 80, "\t");
	print_format("-bwdq: specifies combination of container sizes to match addresses against.", 80, "\t");
	print_format("-b is byte, -w is word (16 bits), -d is doubleword, -q is quadword. Default matches only doublewords.", 80, "\t");
}

// checks [-bwdq] CLI argument for validity
// if valid, pushes specified sizes into input vector S and returns true
// returns false otherwise
bool valid_sizes(const char* sizes, vector<SIZE_T>& s) {
	bool B_SET = false, W_SET = false, D_SET = false, Q_SET = false;
	if (strlen(sizes) <= 1 || strlen(sizes) > 5) { return false; }
	if (sizes[0] != '-') { return false; }
	while (!s.empty()) {
		s.pop_back();
	}
	for (int i = 1; i < strlen(sizes); i++) {
		if ('b' == sizes[i] && !B_SET) {
			s.push_back(1);
			B_SET = true;
		} else if ('w' == sizes[i] && !W_SET) {
			s.push_back(2);
			W_SET = true;
		} else if ('d' == sizes[i] && !D_SET) {
			s.push_back(4);
			D_SET = true;
		} else if ('q' == sizes[i] && !Q_SET) {
			s.push_back(8);
			Q_SET = true;
		} else {
			// if invalid arg, pop everything in S
			while (!s.empty()) {
				s.pop_back();
			}
			return false;
		}
	}
	return true;
}

// simple tests
void run_tests() {
	// TESTS FOR VALID_SIZES()
	vector<SIZE_T> s;
	// simple cases
	assert(valid_sizes("-b", s));
	assert(s.size() == 1 && s.back() == 1);
	s.pop_back();
	// edge cases
	assert(!valid_sizes("-", s));
	assert(!valid_sizes("-z", s));
	assert(!valid_sizes("-bb", s));
	assert(!valid_sizes("-bwdqq", s));
	// order doesn't matter
	assert(valid_sizes("-bwdq", s));
	assert(s.size() == 4);
	assert(*(find(s.begin(), s.end(), 1)) == 1 && *(find(s.begin(), s.end(), 2)) == 2 && *(find(s.begin(), s.end(), 4)) == 4 && *(find(s.begin(), s.end(), 8)) == 8);
	while (!s.empty()) {
		s.pop_back();
	}
	assert(valid_sizes("-qbdw", s));
	assert(s.size() == 4);
	assert(*(find(s.begin(), s.end(), 1)) == 1 && *(find(s.begin(), s.end(), 2)) == 2 && *(find(s.begin(), s.end(), 4)) == 4 && *(find(s.begin(), s.end(), 8)) == 8);

	// TESTS FOR TO_INT()
	// simple cases
	assert(to_int("-") == 0);
	assert(to_int("-1") == -1);
	assert(to_int("3253") == 3253);
	assert(to_int("-92344") == -92344);
	// TESTS FOR TO_HEX()
	assert(to_hex('A') == 10 && to_hex('E') == 14);
	assert(to_hex("FFFF") == HMODULE(65535));
}

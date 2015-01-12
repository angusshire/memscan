// header file for Memscan.cpp

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm> // remove_if()
#include <cassert>
//#define NDEBUG
using namespace std;
#include <windows.h>
#include "utils.h"

// Match struct stores VALUE found at ADDRESS+(SIZE*OFFSET)
typedef struct Match {
	// base address at which value is found
	HMODULE address;
	// value found at ADDRESS+(SIZE*OFFSET)
	DWORD64 value;
	// size of value, in bytes
	size_t size;
	// offset in ADDRESS, in terms of SIZE member
	size_t offset;
} Match;

// Memscan class runs and stores data from a memory scan
class Memscan {
public:
	// scan attributes specify the behavior of the scan; mutually exclusive
	enum class SCAN_ATTRIBUTE {
		// set iff should scan for changes in values in MATCHES; RESCAN must be true
		CHANGED,
		// set iff should scan for unchanged values in MATCHES; RESCAN must be true
		UNCHANGED,
		// set iff should scan for increased values in MATCHES; RESCAN must be true
		INCREASED,
		// set iff should scan for decreased values in MATCHES; RESCAN must be true
		DECREASED,
		// set iff should scan for SCANVALUE in MATCHES
		VALUE,
		// set iff should scan for everything; this is the default
		NONE,
		// set iff should scan for increased floating-point values in MATCHES; RESCAN must be true
		FLOAT_INCREASED,
		// set iff should scan for decreased floating-point values in MATCHES; RESCAN must be true
		FLOAT_DECREASED
	};

	// PUBLIC METHODS
	// constructor sets instance vars
	// args: pin: name of process to be scanned
	Memscan(string pin, PROCESS_MODE process_mode);
	// destructor for Memscan
	~Memscan() {
		deleteMatches();
		deleteFrozen();
		CloseHandle(processHandle);
	}
	// scans memory according to SCANATTRIBUTE, and adds matches to MATCHES
	void scan();
	// prints out specified matches formatted by their Match type
	// args: limit: number of entries to print IN TOTAL (default is 100)
	void printMatches(size_t limit = 100);
	// setter for SIZE_SPECIFIED flag
	// args: b: bool to set flag to; s: vector of sizes to read from memory
	void setSizeSpecified(bool b, vector<SIZE_T>& s);
	// sets SCANATTRIBUTE to specified attribute
	// args: RA: value to set SCANATTRIBUTE to; V: value to set SCANVALUE to
	void setScanAttribute(SCAN_ATTRIBUTE ra, DWORD64 v = 0);
	// begins a new scan for the process by deleting all matches, setting RESCAN to false, reinitializing SIZES, and resetting SCANATTRIBUTE
	void newscan(vector<SIZE_T>& s);
	// adds a Match* to FROZEN
	// args: BASE_ADDRESS: base address of Match; VALUE: value to be written at address BASE_ADDRESS+(SIZE*OFFSET),
	// [args con't] SIZE: size of VALUE, in bytes; OFFSET: offset to BASE_ADDRESS where VALUE is to be written, in terms of SIZE
	void addFrozen(HMODULE base_address, DWORD64 value, size_t size, size_t offset);
	// freezes Matches* in FROZEN at 100ms intervals
	// this method should be called in a secondary thread
	void freeze();
private:
	// MEMBER VARS
	// USER_MODE for user-mode process, KERNEL_MODE for kernel-mode process
	PROCESS_MODE processMode;
	// true iff SIZES is specified
	bool SIZE_SPECIFIED;
	// true iff scan() has been called atleast once
	bool RESCAN;
	// value to scan for
	DWORD64 scanValue;
	// memory units to read
	vector<SIZE_T> sizes;
	// name of process to be scanned
	string processImageName;
	// vector of matching values from calling scan()
	vector<Match*> matches;
	// vector of frozen values from calling addFrozen()
	vector<Match*> frozen;
	// handle to process
	HANDLE processHandle;
	// base address of .exe mapping
	HMODULE baseAddress;
	// specifies scan() behavior
	SCAN_ATTRIBUTE scanAttribute;
	// max and min addresses of VAS
	DWORD64 VAS_MAX, VAS_MIN;

	// HELPER METHODS
	// frees memory and removes everything in MATCHES
	void deleteMatches();
	// adds a Match* to MATCHES
	// args: BASE_ADDRESS: base address of Match; VALUE: value found at address BASE_ADDRESS+(SIZE*OFFSET),
	// [args con't] SIZE: size of VALUE, in bytes; OFFSET: offset to BASE_ADDRESS where VALUE is found, in terms of SIZE
	void addMatch(HMODULE base_address, DWORD64 value, size_t size, size_t offset);
	// processes the MEMBLOCK by finding matches to SCANVALUE (if specified) of specified size; adds matches to MATCHES
	// args: MEMBLOCK: array of read memory values; MEMBLOCK_SIZE: size of memory block; BASE_ADDRESS: address where first value in MEMBLOCK was read
	void processMemblock(DWORD64* memblock, DWORD64 memblock_size, HMODULE base_address);
	// rescans MATCHES with specified attribute
	void rescan();
	// frees memory and removes everything in FROZEN
	void deleteFrozen();
	// sets VAS_MIN and VAS_MAX
	void setVasBounds();
};

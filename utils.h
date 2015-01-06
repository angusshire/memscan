// Author: 4148
// Copyright (c) 2014.
// All rights reserved.

#include <string>
#include <iostream>
using namespace std;
#include "windows.h"
#include "Psapi.h"

// util function prototypes
string basename(string path);
wstring basename(wstring path);
wstring to_wstring(string s);
wstring to_upper(wstring ws);
void print_format(string s, unsigned int width, string delim);
int to_int(string s);
HMODULE to_hex(string s);
DWORD64 to_hex(char c);

// WINAPI utilities
bool check_winapi_error(DWORD expected, DWORD result, string function_name, bool error_exit);
enum PROCESS_MODE { USER_MODE, KERNEL_MODE };
void remove_permissions(HANDLE process_handle, PROCESS_MODE process_mode);
HMODULE get_base_address(HANDLE process_handle, wstring path);

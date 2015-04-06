memscan
=======

`memscan` is a command line utility for scanning a user-mode process's memory. It is compatible with 64-bit Windows, and will not work on 32-bit Windows. For speed, the scan does not support non-aligned addresses.

### Usage

Start a memory scan for a process with 

`memscan <processName>`

That will start a memory scan for the process with default settings.

If you want to specify a value to scan for, enter

`memscan <processName> -v <value>`

You can also specify the combination of memory units you want to scan for (e.g., bytes, words (16-bits), dwords (32-bits), and quadwords (64-bits)). The flags `-b`, `-w`, `-d`, and `-q` correspond to memory unit byte, word, dword, and quadword respectively. Simply combine the flags and add them to the end of the command line statement to scan for these memory units. E.g., 

`memscan <processName> -dq`

Would scan the process for dwords and quadwords.

### License
greenhat is distributed under the GNU General Public License v3.0 (GPLv3).


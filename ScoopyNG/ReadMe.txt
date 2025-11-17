ScoopyNG - The VMware Detection Tool
Version v2.0 - x64 Refactored Edition (2025)

Original Author:  Tobias Klein, 2008 [ www.trapkit.de ]
Modified by: Real Ursus, 2016-2025 (North Pole)

===============================================================================
ABOUT
===============================================================================
ScoopyNG is a comprehensive VMware detection tool that implements multiple
techniques to identify virtualized environments. This tool is designed for
security research, penetration testing, and educational purposes.

===============================================================================
VERSION HISTORY
===============================================================================

Version 2.0 (2025) - Major Refactor
-----------------------------------
* PLATFORM SUPPORT:
  - Full x64 (64-bit) platform support - now the PRIMARY platform
  - Maintained x86 (32-bit) backward compatibility
  - Separate assembly file (ScoopyNG_x64.asm) for x64 low-level operations

* CODE IMPROVEMENTS:
  - Refactored with modern C++ practices (C++14 standard)
  - RAII pattern for resource management (COM objects, memory)
  - Template-based ComPtr smart pointer implementation
  - Class-based architecture with VMwareDetector class
  - Improved error handling and exception safety
  - Better code organization with clear separation of concerns

* BUG FIXES:
  - Fixed MAC address detection bug (was checking incomplete string)
  - Proper VMware MAC prefix detection (00:05:69, 00:0C:29, 00:1C:14, 00:50:56)
  - Corrected x64 detection algorithms for descriptor tables
  - Fixed memory leaks and resource cleanup

* DETECTION ENHANCEMENTS:
  - Updated CPUID detection for modern hypervisors
  - Enhanced descriptor table checks for x64 architecture
  - Improved WMI BIOS detection with better error handling
  - More accurate network adapter enumeration

* BUILD SYSTEM:
  - Updated Visual Studio project for x64 as primary platform
  - MASM integration for x64 assembly compilation
  - C++14 language standard enabled
  - Cleaner project configuration

Version 1.2 (07.05.2016)
------------------------
Added to the original:
 - CPUID Test (0)
 - Virtual BIOS DMI information Test (8)
 - Virtual Adapter Test (9)

Version 1.0 (2008)
------------------
Original release by Tobias Klein
 - IDT Base Address Check (Test 1)
 - LDT Base Address Check (Test 2)
 - GDT Base Address Check (Test 3)
 - Store Task Register Check (Test 4)
 - VMware I/O Port "Get Version" (Test 5)
 - VMware I/O Port "Get Memory Size" (Test 6)
 - VMware Emulation Mode Detection (Test 7)

===============================================================================
DETECTION METHODS
===============================================================================

The tool implements 10 different VMware detection techniques:

Test 0: CPUID Hypervisor Detection
    - Uses CPUID instruction to detect hypervisor presence bit
    - Reads hypervisor vendor string
    - Detects VMware, Hyper-V, and generic hypervisors

Test 1: Interrupt Descriptor Table (IDT) Base
    - Checks IDT base address location
    - VMware typically uses high memory addresses

Test 2: Local Descriptor Table (LDT) Base
    - Examines LDT base address
    - VMware modifies this from expected values

Test 3: Global Descriptor Table (GDT) Base
    - Analyzes GDT base address
    - Detects VMware-specific patterns

Test 4: Store Task Register (STR)
    - Uses STR instruction to read task register
    - VMware typically returns 0x4000

Test 5: VMware I/O Port - Get Version
    - Queries VMware backdoor I/O port (0x5658)
    - Identifies VMware product type (Express, ESX, GSX, Workstation)

Test 6: VMware I/O Port - Get Memory Size
    - Uses VMware backdoor to query memory configuration
    - Only works in VMware environments

Test 7: VMware Emulation Mode Detection
    - Derek Soeder's technique using custom code segments
    - Detects if VMware is running in emulation mode

Test 8: Virtual BIOS DMI Information
    - Queries BIOS serial number via WMI
    - Checks for VMware-specific strings

Test 9: Virtual Network Adapter MAC Address
    - Enumerates network adapters
    - Checks for VMware MAC address prefixes

===============================================================================
BUILDING
===============================================================================

Requirements:
  - Visual Studio 2015 or later (v140 toolset or newer)
  - Windows SDK 8.1 or later
  - MASM (Microsoft Macro Assembler) for x64 builds

Build Configurations:
  - Debug|x64 (PRIMARY)
  - Release|x64 (PRIMARY)
  - Debug|Win32 (Legacy support)
  - Release|Win32 (Legacy support)

To build:
  1. Open ScoopyNG.sln in Visual Studio
  2. Select desired configuration (x64 recommended)
  3. Build Solution (Ctrl+Shift+B)

===============================================================================
USAGE
===============================================================================

Simply run the executable:
    ScoopyNG.exe

The tool will automatically run all detection tests and display results.
No command-line arguments are required.

===============================================================================
TECHNICAL NOTES
===============================================================================

Architecture-Specific Code:
  - x64 builds use external assembly file (ScoopyNG_x64.asm)
  - x86 builds use inline assembly (for backward compatibility)
  - Conditional compilation ensures proper code path selection

Modern C++ Features Used:
  - RAII for resource management
  - Smart pointers (custom ComPtr template)
  - Range-based for loops
  - constexpr for compile-time constants
  - enum class for type safety
  - nullptr instead of NULL

Detection Reliability:
  - Some techniques may be less effective on modern VMware versions
  - Newer VMware versions may hide or mitigate detection
  - Best results when multiple tests confirm virtualization
  - Some tests require specific system configurations

===============================================================================
LICENSE
===============================================================================

See License.txt for BSD license terms.

===============================================================================
CREDITS
===============================================================================

Original Implementation:
  - Tobias Klein (www.trapkit.de) - 2008

Additional Tests and Extensions:
  - Real Ursus (North Pole) - 2016

x64 Refactor and Modernization:
  - Real Ursus - 2025

Detection Techniques Credits:
  - Derek Soeder (eEye Digital Security) - Emulation mode test
  - Alfredo Andrés Omella (S21sec) - STR technique
  - Various security researchers for CPUID and descriptor table methods

===============================================================================
DISCLAIMER
===============================================================================

This tool is provided for educational, research, and authorized security
testing purposes only. Use responsibly and only in environments where you
have explicit permission to perform security testing.

===============================================================================

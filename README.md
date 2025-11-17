# ScoopyNG v3.0 - Multi-Platform Virtualization Detection Tool

**Comprehensive hypervisor detection for Windows 11 24H2 (x64 primary)**

## Overview

ScoopyNG is a comprehensive virtualization detection tool that identifies if software is running inside a virtual machine. Version 3.0 represents a complete refactoring with support for multiple hypervisors and modern C++ design patterns.

## Supported Hypervisors

### Fully Supported (43 detection tests):
- **VMware** (12 tests) - Workstation, ESXi, Fusion
- **Microsoft Hyper-V** (10 tests) - Generation 1 and 2 VMs
- **Oracle VirtualBox** (11 tests) - All versions with Guest Additions
- **KVM/QEMU/Proxmox** (10 tests) - Including VirtIO paravirtualization

### Detection Methods by Category:

#### CPU-Based Detection
- CPUID hypervisor leaf inspection
- Hypervisor vendor string identification
- IDT/GDT/LDT base address analysis
- Task register (STR) inspection

#### Hardware Detection
- BIOS/SMBIOS signatures
- MAC address prefix matching
- PCI device enumeration
- ACPI table inspection

#### Software Detection
- WMI queries (Win32_ComputerSystem, Win32_BIOS, etc.)
- Registry key enumeration
- Driver and service detection
- Running process identification
- File system artifacts

#### VMware-Specific
- I/O backdoor port queries (version, memory)
- VMware Tools detection
- VMware-specific network adapters

#### Hyper-V-Specific
- Integration Services detection
- VM generation identification (Gen1 vs Gen2)
- Synthetic device detection
- VMBus driver detection

#### VirtualBox-Specific
- Guest Additions detection
- VirtualBox-specific devices
- ACPI table signatures

#### QEMU/KVM-Specific
- VirtIO driver detection
- SeaBIOS identification
- Red Hat device signatures
- QEMU device model detection

## Architecture

### Modern C++ Design (C++14)
- **Interface-based architecture** - `IDetectionTest` abstract base class
- **RAII patterns** - Resource management for COM, Registry, WMI
- **Smart pointers** - Memory safety with `std::unique_ptr`
- **Separation of concerns** - Detection logic separate from presentation
- **Extensibility** - Easy to add new hypervisors and tests

### Project Structure
```
ScoopyNG/
├── DetectionTypes.h       - Common types, enums, constants
├── IDetectionTest.h       - Abstract test interface
├── Helpers.h              - Utility classes (COM, WMI, Registry, File)
├── VmwareDetector.h/.cpp  - VMware detection implementations
├── HyperVDetector.h/.cpp  - Hyper-V detection implementations
├── VirtualBoxDetector.h/.cpp - VirtualBox detection implementations
├── ProxmoxDetector.h/.cpp - KVM/QEMU/Proxmox detection implementations
├── main.cpp               - Test orchestration and reporting
└── ScoopyNG_x64.asm       - x64 assembly functions
```

### Key Classes

#### DetectionResult Enum
- `Detected` - Virtualization positively detected
- `NotDetected` - No virtualization found
- `Inconclusive` - Test completed but unclear
- `Error` - Test failed

#### ConfidenceLevel Enum
- `VeryHigh` - Definitive proof (e.g., hypervisor CPUID)
- `High` - Strong indicator (e.g., specific drivers)
- `Medium` - Moderate indicator (e.g., registry keys)
- `Low` - Weak indicator (e.g., single file check)

#### TestResult Structure
```cpp
struct TestResult {
    DetectionResult result;
    HypervisorType hypervisorType;
    ConfidenceLevel confidence;
    std::string testName;
    std::string details;
    uint32_t testId;
};
```

## Building

### Requirements
- Visual Studio 2015+ (v140 toolset)
- Windows SDK 8.1+
- C++14 compiler support
- MASM (Microsoft Macro Assembler) for x64

### Compilation
1. Open `ScoopyNG.sln` in Visual Studio
2. Select configuration: `Release x64` (recommended)
3. Build → Build Solution (Ctrl+Shift+B)

### Output
- `ScoopyNG.exe` - Standalone executable (no dependencies)

## Usage

Simply run the executable:
```
ScoopyNG.exe
```

### Sample Output
```
============================================================
  ScoopyNG - Multi-Platform Virtualization Detection Tool
  Version 3.0 - Comprehensive Hypervisor Detection
  Target: Windows 11 24H2 (x64 Primary)
============================================================

System Information:
  Processors: 4
  Architecture: x64 (64-bit)
  ...

============================================================
  VMware Detection Tests
============================================================

  [100] VMware CPUID Detection
        Details: No VMware CPUID signature found
        Result : Not Detected (Confidence: High)

  ...

============================================================
  Detection Summary
============================================================

  Virtualization Detected!

  Microsoft Hyper-V:
    Detection Count: 8 test(s)
    Max Confidence : Very High

Test Statistics:
  Total Tests Run: 43
  Detections: 8
  Errors: 0
  Success Rate: 100.0%
```

## Detection Test IDs

### VMware (100-111)
- 100: CPUID Detection
- 101: IDT Base Check
- 102: LDT Base Check
- 103: GDT Base Check
- 104: Task Register Check
- 105: I/O Port Version
- 106: I/O Port Memory
- 107: BIOS Serial Check
- 108: MAC Address Check
- 109: Registry Check
- 110: Files Check
- 111: Process Check

### Hyper-V (200-209)
- 200: CPUID Detection
- 201: Registry Check
- 202: WMI Check
- 203: BIOS Check
- 204: Drivers Check
- 205: Services Check
- 206: Integration Services
- 207: Devices Check
- 208: Time Source Check
- 209: Generation Check

### VirtualBox (300-310)
- 300: CPUID Detection
- 301: Registry Check
- 302: WMI Check
- 303: BIOS Check
- 304: MAC Address Check
- 305: Drivers Check
- 306: Files Check
- 307: Process Check
- 308: Devices Check
- 309: ACPI Tables Check
- 310: Firmware Check

### KVM/QEMU/Proxmox (400-409)
- 400: KVM CPUID Detection
- 401: QEMU CPUID Detection
- 402: QEMU BIOS Check
- 403: QEMU WMI Check
- 404: QEMU Devices Check
- 405: QEMU Drivers Check
- 406: QEMU PCI Devices
- 407: QEMU Registry Check
- 408: QEMU Disk Check
- 409: QEMU Network Check

## Use Cases

### Security Research
- VM detection technique analysis
- Anti-analysis bypass research
- Malware sandbox detection

### System Administration
- Verify VM configuration
- Validate guest additions installation
- Infrastructure auditing

### Software Development
- Test application behavior in VMs
- Implement VM-aware features
- Performance optimization for virtualized environments

### Malware Analysis
- Understand malware VM detection capabilities
- Test evasion techniques
- Improve sandbox concealment

## Changelog

### Version 3.0 (2025)
- **NEW**: Hyper-V detection (10 comprehensive tests)
- **NEW**: VirtualBox detection (11 comprehensive tests)
- **NEW**: KVM/QEMU/Proxmox detection (10 comprehensive tests)
- **REFACTORED**: Complete architecture redesign with modern C++
- **IMPROVED**: Modular, extensible detection framework
- **IMPROVED**: Confidence level reporting
- **IMPROVED**: Comprehensive test summary and statistics
- **IMPROVED**: Better error handling and reporting
- **ADDED**: 43 total detection tests across 4 hypervisor families

### Version 2.0 (2016-2025)
- Full x64 platform support (primary platform)
- Refactored detection methods with modern C++ practices
- Separated assembly code to external .asm file
- Fixed MAC address detection bug
- Improved error handling with RAII
- Better code organization and maintainability

### Version 1.2 (2008)
- Original VMware detection implementation
- x86 inline assembly support
- Basic detection methods

## Technical Details

### Assembly Functions (x64)
The x64 assembly module (`ScoopyNG_x64.asm`) provides:
- `GetIdtBase()` - Read IDT base address
- `GetLdtBase()` - Read LDT base selector
- `GetGdtBase()` - Read GDT base address
- `GetTaskRegister()` - Read task register
- `VMwareGetVersion()` - Query VMware I/O backdoor
- `VMwareGetMemorySize()` - Query VMware memory size

### Platform Support
- **Primary**: Windows 11 24H2 x64
- **Tested**: Windows 10/11 x64
- **Legacy**: Windows 7/8/10 x86 (via inline assembly)

### Performance
- Lightweight: ~200KB executable
- Fast: All tests complete in < 1 second
- No dependencies: Self-contained executable

## Limitations

### Known Limitations
- Some tests require administrator privileges (WMI, service enumeration)
- Registry-based detection may fail with restricted permissions
- Driver detection requires appropriate access rights
- Some hypervisors may hide signatures (nested virtualization)

### Detection Evasion
This tool is designed for legitimate purposes. Determined adversaries can:
- Modify hypervisor signatures
- Hide virtual hardware
- Implement anti-detection countermeasures
- Use bare-metal systems

## License

BSD License - See LICENSE.txt for full details

## Credits

- **Original Author**: Tobias Klein, 2008 (www.trapkit.de)
- **Extended by**: Real Ursus, 2016-2025 (North Pole)
- **Version 3.0 Refactoring**: Real Ursus, 2025

## Contributing

This project welcomes contributions:
- New detection methods
- Additional hypervisor support (Xen, Parallels, etc.)
- Bug fixes and improvements
- Documentation enhancements

## References

- Intel® 64 and IA-32 Architectures Software Developer's Manual
- AMD64 Architecture Programmer's Manual
- VMware Backdoor I/O Port Specification
- Microsoft Hyper-V Technical Documentation
- VirtualBox Guest Additions Documentation
- KVM/QEMU Virtualization Guide

## Disclaimer

This tool is provided for educational and research purposes only. Use responsibly and ethically. The authors are not responsible for misuse or any damages caused by this software.

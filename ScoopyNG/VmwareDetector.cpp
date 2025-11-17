/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: VmwareDetector.cpp
 * Purpose: VMware detection test implementations
 */

#include "VmwareDetector.h"
#include <comutil.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "comsuppw.lib")

using namespace HypervisorConstants;
using namespace StringUtils;

// ============================================================================
// VMware CPUID Detection
// ============================================================================

TestResult VMwareCpuidTest::Execute() {
    char hvVendor[13] = { 0 };
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    // Check bit 31 of ECX (hypervisor present bit)
    if ((cpuInfo[2] >> 31) & 1) {
        // Hypervisor is present - get vendor string
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor, cpuInfo + 1, 12);

        if (strcmp(hvVendor, VMWARE_CPUID) == 0) {
            std::string details = "VMware hypervisor detected via CPUID vendor string: ";
            details += hvVendor;
            return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "No VMware CPUID signature found", GetTestId());
}

// ============================================================================
// VMware IDT Base Check
// ============================================================================

TestResult VMwareIdtTest::Execute() {
#if defined(_M_X64) || defined(_M_IX86)
    uintptr_t idtBase = GetIdtBase();
    std::string details = "IDT base: " + FormatHex(idtBase);

#ifdef _M_X64
    // On x64, VMware typically uses high memory addresses
    if ((idtBase >> 40) == 0xFF) {
        details += " - VMware signature detected (high memory address)";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), details, GetTestId());
    }
#else
    // On x86, check if high byte is 0xFF
    if ((idtBase >> 24) == 0xFF) {
        details += " - VMware signature detected (high byte 0xFF)";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), details, GetTestId());
    }
#endif

    details += " - Native pattern detected";
    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
#else
    return TestResult(DetectionResult::Error, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "Platform not supported", GetTestId());
#endif
}

// ============================================================================
// VMware LDT Base Check
// ============================================================================

TestResult VMwareLdtTest::Execute() {
#if defined(_M_X64) || defined(_M_IX86)
    uintptr_t ldtBase = GetLdtBase();
    std::string details = "LDT base: " + FormatHex(ldtBase);

    // On native systems, LDT is typically 0 or specific value
    // VMware modifies this value
    if (ldtBase != 0 && ldtBase != 0xDEADBEEF) {
        details += " - Modified LDT detected (possible VMware)";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
    }

    details += " - Native LDT value";
    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
#else
    return TestResult(DetectionResult::Error, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "Platform not supported", GetTestId());
#endif
}

// ============================================================================
// VMware GDT Base Check
// ============================================================================

TestResult VMwareGdtTest::Execute() {
#if defined(_M_X64) || defined(_M_IX86)
    uintptr_t gdtBase = GetGdtBase();
    std::string details = "GDT base: " + FormatHex(gdtBase);

#ifdef _M_X64
    // On x64, check high bits for VMware signature
    if ((gdtBase >> 40) == 0xFF) {
        details += " - VMware signature detected (high memory address)";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), details, GetTestId());
    }
#else
    // On x86, check if high byte is 0xFF
    if ((gdtBase >> 24) == 0xFF) {
        details += " - VMware signature detected (high byte 0xFF)";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), details, GetTestId());
    }
#endif

    details += " - Native pattern detected";
    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
#else
    return TestResult(DetectionResult::Error, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "Platform not supported", GetTestId());
#endif
}

// ============================================================================
// VMware Task Register Check
// ============================================================================

TestResult VMwareStrTest::Execute() {
#if defined(_M_X64) || defined(_M_IX86)
    uintptr_t taskReg = GetTaskRegister();
    std::ostringstream oss;
    oss << "Task Register: " << FormatHex(taskReg, 4);

    // VMware typically returns 0x4000 for STR
    if (taskReg == 0x4000) {
        oss << " - VMware signature detected";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    oss << " - Native value";
    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), oss.str(), GetTestId());
#else
    return TestResult(DetectionResult::Error, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "Platform not supported", GetTestId());
#endif
}

// ============================================================================
// VMware I/O Port Version Check
// ============================================================================

TestResult VMwareIoPortVersionTest::Execute() {
#ifdef _M_X64
    __try {
        uint64_t result = VMwareGetVersion();
        uint32_t magic = (uint32_t)result;
        uint32_t version = (uint32_t)(result >> 32);

        if (magic == VMWARE_MAGIC) {
            std::ostringstream oss;
            oss << "VMware I/O port accessible - Version: ";
            switch (version) {
            case 1: oss << "Express"; break;
            case 2: oss << "ESX"; break;
            case 3: oss << "GSX"; break;
            case 4: oss << "Workstation"; break;
            default: oss << "Unknown (" << version << ")"; break;
            }

            return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception expected on non-VMware systems
    }
#elif defined(_M_IX86)
    __try {
        uint32_t magic = 0, version = 0;
        __asm {
            push eax
            push ebx
            push ecx
            push edx
            mov eax, VMWARE_MAGIC
            xor ebx, ebx
            mov ecx, 0Ah
            mov dx, VMWARE_PORT
            in eax, dx
            mov magic, ebx
            mov version, ecx
            pop edx
            pop ecx
            pop ebx
            pop eax
        }

        if (magic == VMWARE_MAGIC) {
            std::ostringstream oss;
            oss << "VMware I/O port accessible - Version: ";
            switch (version) {
            case 1: oss << "Express"; break;
            case 2: oss << "ESX"; break;
            case 3: oss << "GSX"; break;
            case 4: oss << "Workstation"; break;
            default: oss << "Unknown (" << version << ")"; break;
            }

            return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception expected on non-VMware systems
    }
#endif

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "VMware I/O port not accessible", GetTestId());
}

// ============================================================================
// VMware I/O Port Memory Check
// ============================================================================

TestResult VMwareIoPortMemoryTest::Execute() {
#ifdef _M_X64
    __try {
        uint64_t memSize = VMwareGetMemorySize();

        if (memSize > 0) {
            std::ostringstream oss;
            oss << "VMware memory query successful: " << memSize << " MB";
            return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception expected on non-VMware systems
    }
#elif defined(_M_IX86)
    __try {
        uint32_t memSize = 0;
        __asm {
            push eax
            push ebx
            push ecx
            push edx
            mov eax, VMWARE_MAGIC
            mov ecx, 14h
            mov dx, VMWARE_PORT
            in eax, dx
            mov memSize, eax
            pop edx
            pop ecx
            pop ebx
            pop eax
        }

        if (memSize > 0) {
            std::ostringstream oss;
            oss << "VMware memory query successful: " << memSize << " MB";
            return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception expected on non-VMware systems
    }
#endif

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "VMware memory query failed", GetTestId());
}

// ============================================================================
// VMware BIOS Serial Check
// ============================================================================

TestResult VMwareBiosTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        std::string serialNumber;
        if (wmi.QueryString(L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber", serialNumber)) {
            if (serialNumber.find("VMware-") == 0 || serialNumber.find("VMW") == 0) {
                std::string details = "VMware BIOS serial detected: " + serialNumber;
                return TestResult(DetectionResult::Detected, HypervisorType::VMware,
                    ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No VMware BIOS signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during BIOS check", GetTestId());
    }
}

// ============================================================================
// VMware MAC Address Check
// ============================================================================

TestResult VMwareMacTest::Execute() {
    ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    std::vector<std::string> vmwareAdapters;

    // Allocate buffer
    pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, outBufLen);
    if (!pAddresses) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Memory allocation failed", GetTestId());
    }

    // Get adapter addresses
    DWORD result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, outBufLen);
        if (!pAddresses) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "Memory allocation failed", GetTestId());
        }
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    }

    if (result != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, pAddresses);
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "GetAdaptersAddresses failed", GetTestId());
    }

    // Check MAC addresses
    PIP_ADAPTER_ADDRESSES pCurr = pAddresses;
    while (pCurr) {
        if (pCurr->PhysicalAddressLength >= 3) {
            for (const auto& prefix : VMWARE_MAC_PREFIXES) {
                if (memcmp(pCurr->PhysicalAddress, prefix, 3) == 0) {
                    std::string mac = FormatMacAddress(pCurr->PhysicalAddress, pCurr->PhysicalAddressLength);
                    vmwareAdapters.push_back("VMware adapter found: " + mac);
                    break;
                }
            }
        }
        pCurr = pCurr->Next;
    }

    HeapFree(GetProcessHeap(), 0, pAddresses);

    if (!vmwareAdapters.empty()) {
        std::ostringstream oss;
        for (const auto& adapter : vmwareAdapters) {
            oss << adapter << "; ";
        }
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VMware MAC addresses found", GetTestId());
}

// ============================================================================
// VMware Registry Check
// ============================================================================

TestResult VMwareRegistryTest::Execute() {
    std::vector<std::string> vmwareKeys = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        "SYSTEM\\ControlSet001\\Services\\Disk\\Enum"
    };

    std::vector<std::string> foundKeys;
    RegistryKey regKey;

    for (const auto& keyPath : vmwareKeys) {
        if (regKey.Open(HKEY_LOCAL_MACHINE, keyPath)) {
            foundKeys.push_back(keyPath);
            regKey.Close();
        }
    }

    // Check for VMware SCSI disk
    if (regKey.Open(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0")) {
        std::string identifier;
        if (regKey.QueryStringValue("Identifier", identifier)) {
            if (ContainsIgnoreCase(identifier, "vmware")) {
                foundKeys.push_back("VMware SCSI disk identifier: " + identifier);
            }
        }
    }

    if (!foundKeys.empty()) {
        std::ostringstream oss;
        oss << "VMware registry keys found: " << foundKeys.size() << " entries";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VMware registry keys found", GetTestId());
}

// ============================================================================
// VMware Files Check
// ============================================================================

TestResult VMwareFilesTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> vmwareFiles = {
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
    };

    std::vector<std::string> foundFiles;

    for (const auto& file : vmwareFiles) {
        if (FileExists(file)) {
            foundFiles.push_back(file);
        }
    }

    // Check for VMware drivers via driver object
    std::vector<std::string> drivers = { "vmmouse", "vmhgfs", "vmci", "vmusbmouse" };
    for (const auto& driver : drivers) {
        if (DriverExists(driver)) {
            foundFiles.push_back("Driver: " + driver);
        }
    }

    if (!foundFiles.empty()) {
        std::ostringstream oss;
        oss << "VMware files/drivers found: " << foundFiles.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VMware files/drivers found", GetTestId());
}

// ============================================================================
// VMware Processes Check
// ============================================================================

TestResult VMwareProcessTest::Execute() {
    using namespace ProcessUtils;

    std::vector<std::string> vmwareProcesses = {
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmacthlp.exe"
    };

    std::vector<std::string> foundProcesses;

    for (const auto& proc : vmwareProcesses) {
        if (IsProcessRunning(proc)) {
            foundProcesses.push_back(proc);
        }
    }

    if (!foundProcesses.empty()) {
        std::ostringstream oss;
        oss << "VMware processes running: ";
        for (size_t i = 0; i < foundProcesses.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << foundProcesses[i];
        }
        return TestResult(DetectionResult::Detected, HypervisorType::VMware,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "No VMware processes detected", GetTestId());
}

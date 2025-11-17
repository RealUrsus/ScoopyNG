/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: VirtualBoxDetector.cpp
 * Purpose: VirtualBox detection test implementations
 */

#include "VirtualBoxDetector.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <sstream>
#include <vector>
#include <tlhelp32.h>

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "IPHLPAPI.lib")

using namespace HypervisorConstants;
using namespace StringUtils;

// ============================================================================
// VirtualBox CPUID Detection
// ============================================================================

TestResult VBoxCpuidTest::Execute() {
    char hvVendor[13] = { 0 };
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    // Check bit 31 of ECX (hypervisor present bit)
    if ((cpuInfo[2] >> 31) & 1) {
        // Hypervisor is present - get vendor string
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor, cpuInfo + 1, 12);

        if (strcmp(hvVendor, VBOX_CPUID) == 0) {
            std::string details = "VirtualBox hypervisor detected via CPUID vendor string: ";
            details += hvVendor;
            return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "No VirtualBox CPUID signature found", GetTestId());
}

// ============================================================================
// VirtualBox Registry Check
// ============================================================================

TestResult VBoxRegistryTest::Execute() {
    RegistryKey regKey;

    // Check for VirtualBox Guest Additions
    if (regKey.Open(HKEY_LOCAL_MACHINE, VBOX_REG_KEY)) {
        std::string version;
        if (regKey.QueryStringValue("Version", version)) {
            std::string details = "VirtualBox Guest Additions detected - Version: " + version;
            return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
        regKey.Close();
    }

    // Check for other VirtualBox registry keys
    std::vector<std::string> vboxKeys = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SYSTEM\\ControlSet001\\Services\\VBoxSF",
        "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
    };

    std::vector<std::string> foundKeys;
    for (const auto& keyPath : vboxKeys) {
        if (regKey.Open(HKEY_LOCAL_MACHINE, keyPath)) {
            foundKeys.push_back(keyPath);
            regKey.Close();
        }
    }

    if (!foundKeys.empty()) {
        std::ostringstream oss;
        oss << "VirtualBox registry keys found: " << foundKeys.size() << " entries";
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VirtualBox registry keys found", GetTestId());
}

// ============================================================================
// VirtualBox WMI Check
// ============================================================================

TestResult VBoxWmiTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check computer system model
        std::string model;
        if (wmi.QueryString(L"SELECT Model FROM Win32_ComputerSystem", L"Model", model)) {
            if (ContainsIgnoreCase(model, "VirtualBox")) {
                std::string details = "VirtualBox model detected: " + model;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        // Check manufacturer
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "innotek") || ContainsIgnoreCase(manufacturer, "Oracle")) {
                std::string details = "VirtualBox manufacturer detected: " + manufacturer;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No VirtualBox WMI signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during WMI check", GetTestId());
    }
}

// ============================================================================
// VirtualBox BIOS Check
// ============================================================================

TestResult VBoxBiosTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check BIOS version for VirtualBox signature
        std::string biosVersion;
        if (wmi.QueryString(L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", L"SMBIOSBIOSVersion", biosVersion)) {
            if (ContainsIgnoreCase(biosVersion, "VBOX") || ContainsIgnoreCase(biosVersion, "VirtualBox")) {
                std::string details = "VirtualBox BIOS version detected: " + biosVersion;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
            }
        }

        // Check BIOS serial number
        std::string serialNumber;
        if (wmi.QueryString(L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber", serialNumber)) {
            if (ContainsIgnoreCase(serialNumber, "VBOX") || serialNumber == "0") {
                std::string details = "VirtualBox BIOS serial detected: " + serialNumber;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No VirtualBox BIOS signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during BIOS check", GetTestId());
    }
}

// ============================================================================
// VirtualBox MAC Address Check
// ============================================================================

TestResult VBoxMacTest::Execute() {
    ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    std::vector<std::string> vboxAdapters;

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
            // VirtualBox uses 08:00:27 prefix
            if (memcmp(pCurr->PhysicalAddress, VBOX_MAC_PREFIX, 3) == 0) {
                std::string mac = FormatMacAddress(pCurr->PhysicalAddress, pCurr->PhysicalAddressLength);
                vboxAdapters.push_back("VirtualBox adapter found: " + mac);
            }
        }
        pCurr = pCurr->Next;
    }

    HeapFree(GetProcessHeap(), 0, pAddresses);

    if (!vboxAdapters.empty()) {
        std::ostringstream oss;
        for (const auto& adapter : vboxAdapters) {
            oss << adapter << "; ";
        }
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VirtualBox MAC addresses found", GetTestId());
}

// ============================================================================
// VirtualBox Drivers Check
// ============================================================================

TestResult VBoxDriversTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> vboxDrivers = {
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\drivers\\VBoxWddm.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\vboxmrxnp.dll",
        "C:\\Windows\\System32\\vboxogl.dll"
    };

    std::vector<std::string> foundDrivers;

    for (const auto& driver : vboxDrivers) {
        if (FileExists(driver)) {
            foundDrivers.push_back(driver);
        }
    }

    // Check for VirtualBox drivers via driver object
    std::vector<std::string> driverNames = {
        "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo", "VBoxWddm"
    };

    for (const auto& driverName : driverNames) {
        if (DriverExists(driverName)) {
            foundDrivers.push_back("Driver: " + driverName);
        }
    }

    if (!foundDrivers.empty()) {
        std::ostringstream oss;
        oss << "VirtualBox drivers found: " << foundDrivers.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VirtualBox drivers found", GetTestId());
}

// ============================================================================
// VirtualBox Files Check
// ============================================================================

TestResult VBoxFilesTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> vboxFiles = {
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxTray.exe",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxControl.exe",
        "C:\\Windows\\System32\\vboxservice.exe",
        "C:\\Windows\\System32\\vboxtray.exe"
    };

    std::vector<std::string> foundFiles;

    for (const auto& file : vboxFiles) {
        if (FileExists(file)) {
            foundFiles.push_back(file);
        }
    }

    // Check for Guest Additions directory
    if (DirectoryExists("C:\\Program Files\\Oracle\\VirtualBox Guest Additions")) {
        foundFiles.push_back("Guest Additions directory");
    }

    if (!foundFiles.empty()) {
        std::ostringstream oss;
        oss << "VirtualBox files found: " << foundFiles.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VirtualBox files found", GetTestId());
}

// ============================================================================
// VirtualBox Processes Check
// ============================================================================

TestResult VBoxProcessTest::Execute() {
    using namespace ProcessUtils;

    std::vector<std::string> vboxProcesses = {
        "VBoxService.exe",
        "VBoxTray.exe",
        "VBoxControl.exe"
    };

    std::vector<std::string> foundProcesses;

    for (const auto& proc : vboxProcesses) {
        if (IsProcessRunning(proc)) {
            foundProcesses.push_back(proc);
        }
    }

    if (!foundProcesses.empty()) {
        std::ostringstream oss;
        oss << "VirtualBox processes running: ";
        for (size_t i = 0; i < foundProcesses.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << foundProcesses[i];
        }
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "No VirtualBox processes detected", GetTestId());
}

// ============================================================================
// VirtualBox Devices Check
// ============================================================================

TestResult VBoxDevicesTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check for VirtualBox PCI devices
        std::vector<std::string> devices;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_PnPEntity", L"Name", devices)) {
            int vboxDeviceCount = 0;
            for (const auto& device : devices) {
                if (ContainsIgnoreCase(device, "VBox") ||
                    ContainsIgnoreCase(device, "VirtualBox") ||
                    ContainsIgnoreCase(device, "Oracle")) {
                    vboxDeviceCount++;
                }
            }

            if (vboxDeviceCount > 0) {
                std::ostringstream oss;
                oss << "VirtualBox devices found: " << vboxDeviceCount << " devices";
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No VirtualBox devices found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during device check", GetTestId());
    }
}

// ============================================================================
// VirtualBox ACPI Tables Check
// ============================================================================

TestResult VBoxAcpiTest::Execute() {
    RegistryKey regKey;

    // Check ACPI tables for VirtualBox signatures
    std::vector<std::string> acpiKeys = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__"
    };

    std::vector<std::string> foundKeys;
    for (const auto& keyPath : acpiKeys) {
        if (regKey.Open(HKEY_LOCAL_MACHINE, keyPath)) {
            foundKeys.push_back(keyPath);
            regKey.Close();
        }
    }

    if (!foundKeys.empty()) {
        std::ostringstream oss;
        oss << "VirtualBox ACPI tables found: " << foundKeys.size() << " entries";
        return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No VirtualBox ACPI tables found", GetTestId());
}

// ============================================================================
// VirtualBox Firmware Check
// ============================================================================

TestResult VBoxFirmwareTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check baseboard manufacturer and product
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_BaseBoard", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "Oracle") || ContainsIgnoreCase(manufacturer, "innotek")) {
                std::string details = "VirtualBox baseboard manufacturer: " + manufacturer;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        std::string product;
        if (wmi.QueryString(L"SELECT Product FROM Win32_BaseBoard", L"Product", product)) {
            if (ContainsIgnoreCase(product, "VirtualBox")) {
                std::string details = "VirtualBox baseboard product: " + product;
                return TestResult(DetectionResult::Detected, HypervisorType::VirtualBox,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No VirtualBox firmware signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during firmware check", GetTestId());
    }
}

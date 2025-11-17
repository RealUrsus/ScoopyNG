/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: HyperVDetector.cpp
 * Purpose: Hyper-V detection test implementations
 */

#include "HyperVDetector.h"
#include <sstream>
#include <vector>
#include <tlhelp32.h>

#pragma comment(lib, "comsuppw.lib")

using namespace HypervisorConstants;
using namespace StringUtils;

// ============================================================================
// Hyper-V CPUID Detection
// ============================================================================

TestResult HyperVCpuidTest::Execute() {
    char hvVendor[13] = { 0 };
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    // Check bit 31 of ECX (hypervisor present bit)
    if ((cpuInfo[2] >> 31) & 1) {
        // Hypervisor is present - get vendor string
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor, cpuInfo + 1, 12);

        if (strcmp(hvVendor, HYPERV_CPUID) == 0) {
            // Get additional Hyper-V information
            __cpuid(cpuInfo, 0x40000003);
            bool isRootPartition = (cpuInfo[1] & 1) != 0;

            std::ostringstream oss;
            oss << "Hyper-V detected via CPUID - ";
            oss << (isRootPartition ? "Root partition (Host)" : "Child partition (Guest)");

            return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
        }
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "No Hyper-V CPUID signature found", GetTestId());
}

// ============================================================================
// Hyper-V Registry Check
// ============================================================================

TestResult HyperVRegistryTest::Execute() {
    RegistryKey regKey;

    // Check for Hyper-V Guest Parameters
    if (regKey.Open(HKEY_LOCAL_MACHINE, HYPERV_REG_KEY)) {
        std::string hostName;
        if (regKey.QueryStringValue(HYPERV_PHYS_HOST_KEY, hostName)) {
            std::string details = "Hyper-V guest detected - Physical host: " + hostName;
            return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
        regKey.Close();
    }

    // Check for Hyper-V Integration Services
    std::vector<std::string> hypervKeys = {
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest",
        "SOFTWARE\\Microsoft\\Hyper-V\\Guest",
        "SYSTEM\\ControlSet001\\Services\\vmbus",
        "SYSTEM\\ControlSet001\\Services\\VMBusHID"
    };

    std::vector<std::string> foundKeys;
    for (const auto& keyPath : hypervKeys) {
        if (regKey.Open(HKEY_LOCAL_MACHINE, keyPath)) {
            foundKeys.push_back(keyPath);
            regKey.Close();
        }
    }

    if (!foundKeys.empty()) {
        std::ostringstream oss;
        oss << "Hyper-V registry keys found: " << foundKeys.size() << " entries";
        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No Hyper-V registry keys found", GetTestId());
}

// ============================================================================
// Hyper-V WMI Check
// ============================================================================

TestResult HyperVWmiTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check computer system model
        std::string model;
        if (wmi.QueryString(L"SELECT Model FROM Win32_ComputerSystem", L"Model", model)) {
            if (ContainsIgnoreCase(model, "Virtual Machine")) {
                std::string details = "Hyper-V Virtual Machine detected: " + model;
                return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        // Check manufacturer
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "Microsoft Corporation")) {
                // Additional check to confirm it's Hyper-V
                if (wmi.QueryString(L"SELECT Model FROM Win32_ComputerSystem", L"Model", model)) {
                    if (ContainsIgnoreCase(model, "Virtual")) {
                        std::string details = "Microsoft Virtual Machine detected: " + model;
                        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                            ConfidenceLevel::High, GetTestName(), details, GetTestId());
                    }
                }
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No Hyper-V WMI signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during WMI check", GetTestId());
    }
}

// ============================================================================
// Hyper-V BIOS Check
// ============================================================================

TestResult HyperVBiosTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check BIOS version for Hyper-V signature
        std::string biosVersion;
        if (wmi.QueryString(L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", L"SMBIOSBIOSVersion", biosVersion)) {
            if (ContainsIgnoreCase(biosVersion, "Hyper-V") ||
                ContainsIgnoreCase(biosVersion, "VRTUAL") ||
                ContainsIgnoreCase(biosVersion, "A M I")) {
                std::string details = "Hyper-V BIOS version detected: " + biosVersion;
                return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        // Check BIOS manufacturer
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "Microsoft Corporation")) {
                std::string details = "Microsoft BIOS manufacturer detected";
                return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                    ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No Hyper-V BIOS signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during BIOS check", GetTestId());
    }
}

// ============================================================================
// Hyper-V Drivers Check
// ============================================================================

TestResult HyperVDriversTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> hypervDrivers = {
        "C:\\Windows\\System32\\drivers\\vmbus.sys",
        "C:\\Windows\\System32\\drivers\\storvsc.sys",
        "C:\\Windows\\System32\\drivers\\netvsc.sys",
        "C:\\Windows\\System32\\drivers\\vmbusdrv.sys",
        "C:\\Windows\\System32\\drivers\\hypervideo.sys",
        "C:\\Windows\\System32\\drivers\\hyperkbd.sys"
    };

    std::vector<std::string> foundDrivers;

    for (const auto& driver : hypervDrivers) {
        if (FileExists(driver)) {
            foundDrivers.push_back(driver);
        }
    }

    // Check for Hyper-V drivers via driver object
    std::vector<std::string> driverNames = {
        "vmbus", "storvsc", "netvsc", "hypervideo", "hyperkbd"
    };

    for (const auto& driverName : driverNames) {
        if (DriverExists(driverName)) {
            foundDrivers.push_back("Driver: " + driverName);
        }
    }

    if (!foundDrivers.empty()) {
        std::ostringstream oss;
        oss << "Hyper-V drivers found: " << foundDrivers.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No Hyper-V drivers found", GetTestId());
}

// ============================================================================
// Hyper-V Services Check
// ============================================================================

TestResult HyperVServicesTest::Execute() {
    using namespace ServiceUtils;

    std::vector<std::string> hypervServices = {
        "vmbus",
        "vmicheartbeat",
        "vmickvpexchange",
        "vmicshutdown",
        "vmictimesync",
        "vmicvss",
        "vmicrdv"
    };

    std::vector<std::string> foundServices;

    for (const auto& service : hypervServices) {
        if (ServiceExists(service)) {
            foundServices.push_back(service);
        }
    }

    if (!foundServices.empty()) {
        std::ostringstream oss;
        oss << "Hyper-V services found: " << foundServices.size() << " services";
        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "No Hyper-V services found", GetTestId());
}

// ============================================================================
// Hyper-V Integration Services Check
// ============================================================================

TestResult HyperVIntegrationTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> integrationFiles = {
        "C:\\Windows\\System32\\vmGuestLib.dll",
        "C:\\Windows\\System32\\vm3dservice.exe",
        "C:\\Windows\\System32\\vmictimeprovider.dll"
    };

    std::vector<std::string> foundFiles;

    for (const auto& file : integrationFiles) {
        if (FileExists(file)) {
            foundFiles.push_back(file);
        }
    }

    // Check for Integration Services in Program Files
    if (DirectoryExists("C:\\Program Files\\Hyper-V Integration Services")) {
        foundFiles.push_back("Integration Services directory");
    }

    if (!foundFiles.empty()) {
        std::ostringstream oss;
        oss << "Hyper-V Integration Services found: " << foundFiles.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "No Integration Services found", GetTestId());
}

// ============================================================================
// Hyper-V Devices Check
// ============================================================================

TestResult HyperVDevicesTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check for Hyper-V devices
        std::vector<std::string> devices;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_PnPEntity", L"Name", devices)) {
            int hypervDeviceCount = 0;
            for (const auto& device : devices) {
                if (ContainsIgnoreCase(device, "Hyper-V") ||
                    ContainsIgnoreCase(device, "Microsoft Virtual") ||
                    ContainsIgnoreCase(device, "Synthetic")) {
                    hypervDeviceCount++;
                }
            }

            if (hypervDeviceCount > 0) {
                std::ostringstream oss;
                oss << "Hyper-V virtual devices found: " << hypervDeviceCount << " devices";
                return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                    ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No Hyper-V devices found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during device check", GetTestId());
    }
}

// ============================================================================
// Hyper-V Time Source Check
// ============================================================================

TestResult HyperVTimeSourceTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check if VM time synchronization service exists
        std::vector<std::string> services;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_Service WHERE Name LIKE '%vmic%'", L"Name", services)) {
            for (const auto& service : services) {
                if (ContainsIgnoreCase(service, "time")) {
                    std::string details = "Hyper-V time synchronization service found: " + service;
                    return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                        ConfidenceLevel::Medium, GetTestName(), details, GetTestId());
                }
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "No Hyper-V time source found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during time source check", GetTestId());
    }
}

// ============================================================================
// Hyper-V Generation Check
// ============================================================================

TestResult HyperVGenerationTest::Execute() {
    using namespace FileUtils;

    // Generation 2 VMs use UEFI firmware
    // Generation 1 VMs use BIOS firmware

    // Check for UEFI indicators (Generation 2)
    if (DirectoryExists("C:\\EFI") || FileExists("C:\\Windows\\System32\\efisys.bin")) {
        try {
            WmiQuery wmi;
            if (wmi.Initialize()) {
                std::string model;
                if (wmi.QueryString(L"SELECT Model FROM Win32_ComputerSystem", L"Model", model)) {
                    if (ContainsIgnoreCase(model, "Virtual Machine")) {
                        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
                            ConfidenceLevel::Medium, GetTestName(),
                            "Hyper-V Generation 2 VM detected (UEFI)", GetTestId());
                    }
                }
            }
        }
        catch (...) {
            // Continue with detection
        }
    }

    // Check for BIOS indicators (Generation 1)
    RegistryKey regKey;
    if (regKey.Open(HKEY_LOCAL_MACHINE, HYPERV_REG_KEY)) {
        return TestResult(DetectionResult::Detected, HypervisorType::HyperV,
            ConfidenceLevel::Low, GetTestName(),
            "Hyper-V VM detected (Generation undetermined)", GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Low, GetTestName(), "Not a Hyper-V VM", GetTestId());
}

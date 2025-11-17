/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: ProxmoxDetector.cpp
 * Purpose: Proxmox/KVM/QEMU detection test implementations
 */

#include "ProxmoxDetector.h"
#include <sstream>
#include <vector>

#pragma comment(lib, "comsuppw.lib")

using namespace HypervisorConstants;
using namespace StringUtils;

// ============================================================================
// KVM CPUID Detection
// ============================================================================

TestResult KvmCpuidTest::Execute() {
    char hvVendor[13] = { 0 };
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    // Check bit 31 of ECX (hypervisor present bit)
    if ((cpuInfo[2] >> 31) & 1) {
        // Hypervisor is present - get vendor string
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor, cpuInfo + 1, 12);

        if (strncmp(hvVendor, KVM_CPUID, 12) == 0) {
            std::string details = "KVM hypervisor detected via CPUID vendor string: ";
            details += hvVendor;
            return TestResult(DetectionResult::Detected, HypervisorType::KVM,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "No KVM CPUID signature found", GetTestId());
}

// ============================================================================
// QEMU CPUID Detection
// ============================================================================

TestResult QemuCpuidTest::Execute() {
    char hvVendor[13] = { 0 };
    int cpuInfo[4] = { -1 };

    __cpuid(cpuInfo, 1);

    // Check bit 31 of ECX (hypervisor present bit)
    if ((cpuInfo[2] >> 31) & 1) {
        // Hypervisor is present - get vendor string
        __cpuid(cpuInfo, 0x40000000);
        memcpy(hvVendor, cpuInfo + 1, 12);

        if (strcmp(hvVendor, QEMU_CPUID) == 0) {
            std::string details = "QEMU/TCG detected via CPUID vendor string: ";
            details += hvVendor;
            return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
        }
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::High, GetTestName(), "No QEMU CPUID signature found", GetTestId());
}

// ============================================================================
// QEMU BIOS Check
// ============================================================================

TestResult QemuBiosTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check BIOS version for QEMU/SeaBIOS signature
        std::string biosVersion;
        if (wmi.QueryString(L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", L"SMBIOSBIOSVersion", biosVersion)) {
            if (ContainsIgnoreCase(biosVersion, "QEMU") ||
                ContainsIgnoreCase(biosVersion, "SeaBIOS") ||
                ContainsIgnoreCase(biosVersion, "Bochs")) {
                std::string details = "QEMU BIOS version detected: " + biosVersion;
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
            }
        }

        // Check BIOS manufacturer
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "QEMU") ||
                ContainsIgnoreCase(manufacturer, "SeaBIOS")) {
                std::string details = "QEMU BIOS manufacturer detected: " + manufacturer;
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::VeryHigh, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU BIOS signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during BIOS check", GetTestId());
    }
}

// ============================================================================
// QEMU WMI Check
// ============================================================================

TestResult QemuWmiTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check computer system model
        std::string model;
        if (wmi.QueryString(L"SELECT Model FROM Win32_ComputerSystem", L"Model", model)) {
            if (ContainsIgnoreCase(model, "QEMU") ||
                ContainsIgnoreCase(model, "Standard PC") ||
                ContainsIgnoreCase(model, "KVM")) {
                std::string details = "QEMU/KVM model detected: " + model;
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        // Check manufacturer
        std::string manufacturer;
        if (wmi.QueryString(L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer", manufacturer)) {
            if (ContainsIgnoreCase(manufacturer, "QEMU") ||
                ContainsIgnoreCase(manufacturer, "Red Hat") ||
                ContainsIgnoreCase(manufacturer, "oVirt")) {
                std::string details = "QEMU manufacturer detected: " + manufacturer;
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::High, GetTestName(), details, GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU WMI signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during WMI check", GetTestId());
    }
}

// ============================================================================
// QEMU Devices Check
// ============================================================================

TestResult QemuDevicesTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check for QEMU/VirtIO devices
        std::vector<std::string> devices;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_PnPEntity", L"Name", devices)) {
            int qemuDeviceCount = 0;
            std::vector<std::string> qemuDevices;

            for (const auto& device : devices) {
                if (ContainsIgnoreCase(device, "QEMU") ||
                    ContainsIgnoreCase(device, "VirtIO") ||
                    ContainsIgnoreCase(device, "Red Hat")) {
                    qemuDeviceCount++;
                    qemuDevices.push_back(device);
                }
            }

            if (qemuDeviceCount > 0) {
                std::ostringstream oss;
                oss << "QEMU/VirtIO devices found: " << qemuDeviceCount << " devices";
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU devices found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during device check", GetTestId());
    }
}

// ============================================================================
// QEMU Drivers Check
// ============================================================================

TestResult QemuDriversTest::Execute() {
    using namespace FileUtils;

    std::vector<std::string> qemuDrivers = {
        "C:\\Windows\\System32\\drivers\\balloon.sys",
        "C:\\Windows\\System32\\drivers\\netkvm.sys",
        "C:\\Windows\\System32\\drivers\\vioser.sys",
        "C:\\Windows\\System32\\drivers\\viostor.sys",
        "C:\\Windows\\System32\\drivers\\vioscsi.sys",
        "C:\\Windows\\System32\\drivers\\viorng.sys",
        "C:\\Windows\\System32\\drivers\\qemufwcfg.sys"
    };

    std::vector<std::string> foundDrivers;

    for (const auto& driver : qemuDrivers) {
        if (FileExists(driver)) {
            foundDrivers.push_back(driver);
        }
    }

    // Check for VirtIO drivers via driver object
    std::vector<std::string> driverNames = {
        "balloon", "netkvm", "vioser", "viostor", "vioscsi", "viorng"
    };

    for (const auto& driverName : driverNames) {
        if (DriverExists(driverName)) {
            foundDrivers.push_back("Driver: " + driverName);
        }
    }

    if (!foundDrivers.empty()) {
        std::ostringstream oss;
        oss << "QEMU/VirtIO drivers found: " << foundDrivers.size() << " items";
        return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
            ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No QEMU drivers found", GetTestId());
}

// ============================================================================
// QEMU PCI Devices Check
// ============================================================================

TestResult QemuPciTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check PCI devices for QEMU identifiers
        std::vector<std::string> pciDevices;
        if (wmi.QueryAll(L"SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE 'PCI%'", L"DeviceID", pciDevices)) {
            int qemuPciCount = 0;

            for (const auto& device : pciDevices) {
                // QEMU PCI vendor ID is 1AF4 (Red Hat) and 1B36 (QEMU)
                if (ContainsIgnoreCase(device, "VEN_1AF4") ||
                    ContainsIgnoreCase(device, "VEN_1B36") ||
                    ContainsIgnoreCase(device, "VEN_1234")) {  // QEMU VGA
                    qemuPciCount++;
                }
            }

            if (qemuPciCount > 0) {
                std::ostringstream oss;
                oss << "QEMU PCI devices found: " << qemuPciCount << " devices";
                return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                    ConfidenceLevel::VeryHigh, GetTestName(), oss.str(), GetTestId());
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU PCI devices found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during PCI check", GetTestId());
    }
}

// ============================================================================
// QEMU Registry Check
// ============================================================================

TestResult QemuRegistryTest::Execute() {
    RegistryKey regKey;

    std::vector<std::string> qemuKeys = {
        "SYSTEM\\ControlSet001\\Services\\balloon",
        "SYSTEM\\ControlSet001\\Services\\netkvm",
        "SYSTEM\\ControlSet001\\Services\\vioser",
        "SYSTEM\\ControlSet001\\Services\\viostor",
        "SYSTEM\\ControlSet001\\Services\\vioscsi",
        "SOFTWARE\\Red Hat\\Virtio-Win"
    };

    std::vector<std::string> foundKeys;
    for (const auto& keyPath : qemuKeys) {
        if (regKey.Open(HKEY_LOCAL_MACHINE, keyPath)) {
            foundKeys.push_back(keyPath);
            regKey.Close();
        }
    }

    if (!foundKeys.empty()) {
        std::ostringstream oss;
        oss << "QEMU/VirtIO registry keys found: " << foundKeys.size() << " entries";
        return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
            ConfidenceLevel::High, GetTestName(), oss.str(), GetTestId());
    }

    return TestResult(DetectionResult::NotDetected, HypervisorType::None,
        ConfidenceLevel::Medium, GetTestName(), "No QEMU registry keys found", GetTestId());
}

// ============================================================================
// QEMU Disk Check
// ============================================================================

TestResult QemuDiskTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check disk drives for QEMU signature
        std::vector<std::string> diskModels;
        if (wmi.QueryAll(L"SELECT Model FROM Win32_DiskDrive", L"Model", diskModels)) {
            for (const auto& model : diskModels) {
                if (ContainsIgnoreCase(model, "QEMU") ||
                    ContainsIgnoreCase(model, "VBOX") ||  // Sometimes QEMU uses VBOX
                    ContainsIgnoreCase(model, "Red Hat VirtIO")) {
                    std::string details = "QEMU disk detected: " + model;
                    return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                        ConfidenceLevel::High, GetTestName(), details, GetTestId());
                }
            }
        }

        // Check for IDE/SCSI controller
        std::vector<std::string> controllers;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_SCSIController", L"Name", controllers)) {
            for (const auto& controller : controllers) {
                if (ContainsIgnoreCase(controller, "Red Hat") ||
                    ContainsIgnoreCase(controller, "VirtIO")) {
                    std::string details = "QEMU SCSI controller detected: " + controller;
                    return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                        ConfidenceLevel::High, GetTestName(), details, GetTestId());
                }
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU disk signature found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during disk check", GetTestId());
    }
}

// ============================================================================
// QEMU Network Check
// ============================================================================

TestResult QemuNetworkTest::Execute() {
    try {
        WmiQuery wmi;
        if (!wmi.Initialize()) {
            return TestResult(DetectionResult::Error, HypervisorType::None,
                ConfidenceLevel::Low, GetTestName(), "WMI initialization failed", GetTestId());
        }

        // Check network adapters for VirtIO/QEMU signature
        std::vector<std::string> adapters;
        if (wmi.QueryAll(L"SELECT Name FROM Win32_NetworkAdapter", L"Name", adapters)) {
            for (const auto& adapter : adapters) {
                if (ContainsIgnoreCase(adapter, "Red Hat VirtIO") ||
                    ContainsIgnoreCase(adapter, "QEMU") ||
                    ContainsIgnoreCase(adapter, "Ethernet Adapter")) {
                    std::string details = "QEMU network adapter detected: " + adapter;
                    return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                        ConfidenceLevel::High, GetTestName(), details, GetTestId());
                }
            }
        }

        // Check adapter descriptions
        if (wmi.QueryAll(L"SELECT Description FROM Win32_NetworkAdapter", L"Description", adapters)) {
            for (const auto& adapter : adapters) {
                if (ContainsIgnoreCase(adapter, "VirtIO") ||
                    ContainsIgnoreCase(adapter, "Red Hat")) {
                    std::string details = "VirtIO network adapter detected: " + adapter;
                    return TestResult(DetectionResult::Detected, HypervisorType::QEMU,
                        ConfidenceLevel::High, GetTestName(), details, GetTestId());
                }
            }
        }

        return TestResult(DetectionResult::NotDetected, HypervisorType::None,
            ConfidenceLevel::Medium, GetTestName(), "No QEMU network adapter found", GetTestId());
    }
    catch (...) {
        return TestResult(DetectionResult::Error, HypervisorType::None,
            ConfidenceLevel::Low, GetTestName(), "Exception during network check", GetTestId());
    }
}

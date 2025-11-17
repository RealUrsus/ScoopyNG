/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * Original Author: Tobias Klein, 2008 [ www.trapkit.de ]
 * Modified by: Real Ursus, 2016-2025 (North Pole)
 *
 * Changelog v3.0:
 * - Added support for Hyper-V, VirtualBox, KVM, and QEMU/Proxmox detection
 * - Refactored architecture with abstraction layer
 * - Modern C++ design patterns (interfaces, RAII, smart pointers)
 * - Comprehensive detection methods for each hypervisor
 * - Improved code organization and maintainability
 * - Enhanced reporting with confidence levels
 */

#include "DetectionTypes.h"
#include "IDetectionTest.h"
#include "Helpers.h"
#include "VmwareDetector.h"
#include "HyperVDetector.h"
#include "VirtualBoxDetector.h"
#include "ProxmoxDetector.h"

#include <windows.h>
#include <iostream>
#include <vector>
#include <memory>
#include <iomanip>
#include <map>

using namespace std;

// ============================================================================
// Banner and System Information
// ============================================================================

void PrintBanner() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "  ScoopyNG - Multi-Platform Virtualization Detection Tool\n";
    cout << "  Version 3.0 - Comprehensive Hypervisor Detection\n";
    cout << "  Target: Windows 11 24H2 (x64 Primary)\n";
    cout << "============================================================\n\n";
}

void PrintSystemInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    cout << "System Information:\n";
    cout << "  Processors: " << sysInfo.dwNumberOfProcessors << "\n";
    cout << "  Processor Type: " << sysInfo.dwProcessorType << "\n";

#ifdef _M_X64
    cout << "  Architecture: x64 (64-bit)\n";
#elif defined(_M_IX86)
    cout << "  Architecture: x86 (32-bit)\n";
#elif defined(_M_ARM64)
    cout << "  Architecture: ARM64\n";
#else
    cout << "  Architecture: Unknown\n";
#endif

    cout << "  Page Size: " << sysInfo.dwPageSize << " bytes\n";

    // Calculate uptime
    DWORD uptime = GetTickCount();
    unsigned int days = uptime / (24 * 60 * 60 * 1000);
    uptime %= (24 * 60 * 60 * 1000);
    unsigned int hours = uptime / (60 * 60 * 1000);
    uptime %= (60 * 60 * 1000);
    unsigned int minutes = uptime / (60 * 1000);

    cout << "  System Uptime: " << days << " days, " << hours << " hours, "
        << minutes << " minutes\n\n";
}

// ============================================================================
// Test Execution and Reporting
// ============================================================================

void PrintTestResult(const TestResult& result) {
    cout << "  [" << setw(3) << result.testId << "] " << result.testName << "\n";
    cout << "        Details: " << result.details << "\n";
    cout << "        Result : ";

    switch (result.result) {
    case DetectionResult::Detected:
        cout << "DETECTED - " << GetHypervisorName(result.hypervisorType);
        break;
    case DetectionResult::NotDetected:
        cout << "Not Detected";
        break;
    case DetectionResult::Inconclusive:
        cout << "Inconclusive";
        break;
    case DetectionResult::Error:
        cout << "Error";
        break;
    }

    cout << " (Confidence: " << GetConfidenceName(result.confidence) << ")\n\n";
}

void PrintSectionHeader(const string& title) {
    cout << "\n============================================================\n";
    cout << "  " << title << "\n";
    cout << "============================================================\n\n";
}

void PrintDetectionSummary(const vector<TestResult>& allResults) {
    PrintSectionHeader("Detection Summary");

    map<HypervisorType, int> detectionCounts;
    map<HypervisorType, ConfidenceLevel> maxConfidence;

    for (const auto& result : allResults) {
        if (result.IsDetected()) {
            detectionCounts[result.hypervisorType]++;

            if (maxConfidence.find(result.hypervisorType) == maxConfidence.end() ||
                result.confidence > maxConfidence[result.hypervisorType]) {
                maxConfidence[result.hypervisorType] = result.confidence;
            }
        }
    }

    if (detectionCounts.empty()) {
        cout << "  No virtualization detected - Running on native hardware\n\n";
    }
    else {
        cout << "  Virtualization Detected!\n\n";
        for (const auto& kvp : detectionCounts) {
            cout << "  " << GetHypervisorName(kvp.first) << ":\n";
            cout << "    Detection Count: " << kvp.second << " test(s)\n";
            cout << "    Max Confidence : " << GetConfidenceName(maxConfidence[kvp.first]) << "\n\n";
        }
    }

    // Statistics
    int totalTests = static_cast<int>(allResults.size());
    int detectedTests = 0;
    int errorTests = 0;

    for (const auto& result : allResults) {
        if (result.IsDetected()) detectedTests++;
        if (result.IsError()) errorTests++;
    }

    cout << "Test Statistics:\n";
    cout << "  Total Tests Run: " << totalTests << "\n";
    cout << "  Detections: " << detectedTests << "\n";
    cout << "  Errors: " << errorTests << "\n";
    cout << "  Success Rate: " << fixed << setprecision(1)
        << (100.0 * (totalTests - errorTests) / totalTests) << "%\n\n";
}

// ============================================================================
// Test Registration and Execution
// ============================================================================

void RegisterAllTests(vector<DetectionTestPtr>& tests) {
    // VMware Tests
    tests.push_back(make_unique<VMwareCpuidTest>());
    tests.push_back(make_unique<VMwareIdtTest>());
    tests.push_back(make_unique<VMwareLdtTest>());
    tests.push_back(make_unique<VMwareGdtTest>());
    tests.push_back(make_unique<VMwareStrTest>());
    tests.push_back(make_unique<VMwareIoPortVersionTest>());
    tests.push_back(make_unique<VMwareIoPortMemoryTest>());
    tests.push_back(make_unique<VMwareBiosTest>());
    tests.push_back(make_unique<VMwareMacTest>());
    tests.push_back(make_unique<VMwareRegistryTest>());
    tests.push_back(make_unique<VMwareFilesTest>());
    tests.push_back(make_unique<VMwareProcessTest>());

    // Hyper-V Tests
    tests.push_back(make_unique<HyperVCpuidTest>());
    tests.push_back(make_unique<HyperVRegistryTest>());
    tests.push_back(make_unique<HyperVWmiTest>());
    tests.push_back(make_unique<HyperVBiosTest>());
    tests.push_back(make_unique<HyperVDriversTest>());
    tests.push_back(make_unique<HyperVServicesTest>());
    tests.push_back(make_unique<HyperVIntegrationTest>());
    tests.push_back(make_unique<HyperVDevicesTest>());
    tests.push_back(make_unique<HyperVTimeSourceTest>());
    tests.push_back(make_unique<HyperVGenerationTest>());

    // VirtualBox Tests
    tests.push_back(make_unique<VBoxCpuidTest>());
    tests.push_back(make_unique<VBoxRegistryTest>());
    tests.push_back(make_unique<VBoxWmiTest>());
    tests.push_back(make_unique<VBoxBiosTest>());
    tests.push_back(make_unique<VBoxMacTest>());
    tests.push_back(make_unique<VBoxDriversTest>());
    tests.push_back(make_unique<VBoxFilesTest>());
    tests.push_back(make_unique<VBoxProcessTest>());
    tests.push_back(make_unique<VBoxDevicesTest>());
    tests.push_back(make_unique<VBoxAcpiTest>());
    tests.push_back(make_unique<VBoxFirmwareTest>());

    // KVM/QEMU/Proxmox Tests
    tests.push_back(make_unique<KvmCpuidTest>());
    tests.push_back(make_unique<QemuCpuidTest>());
    tests.push_back(make_unique<QemuBiosTest>());
    tests.push_back(make_unique<QemuWmiTest>());
    tests.push_back(make_unique<QemuDevicesTest>());
    tests.push_back(make_unique<QemuDriversTest>());
    tests.push_back(make_unique<QemuPciTest>());
    tests.push_back(make_unique<QemuRegistryTest>());
    tests.push_back(make_unique<QemuDiskTest>());
    tests.push_back(make_unique<QemuNetworkTest>());
}

void RunAllTests(vector<TestResult>& results) {
    vector<DetectionTestPtr> tests;
    RegisterAllTests(tests);

    // Group tests by hypervisor for better output
    map<HypervisorType, vector<IDetectionTest*>> testsByHypervisor;

    for (const auto& test : tests) {
        testsByHypervisor[test->GetTargetHypervisor()].push_back(test.get());
    }

    // Run tests grouped by hypervisor type
    const HypervisorType hypervisors[] = {
        HypervisorType::VMware,
        HypervisorType::HyperV,
        HypervisorType::VirtualBox,
        HypervisorType::KVM,
        HypervisorType::QEMU
    };

    for (auto hvType : hypervisors) {
        if (testsByHypervisor.find(hvType) == testsByHypervisor.end()) {
            continue;
        }

        PrintSectionHeader(string(GetHypervisorName(hvType)) + " Detection Tests");

        for (auto* test : testsByHypervisor[hvType]) {
            if (test->IsPlatformSupported()) {
                TestResult result = test->Execute();
                results.push_back(result);
                PrintTestResult(result);
            }
            else {
                cout << "  [" << setw(3) << test->GetTestId() << "] " << test->GetTestName() << "\n";
                cout << "        Result : Platform not supported\n\n";
            }
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    try {
        PrintBanner();
        PrintSystemInfo();

        vector<TestResult> allResults;
        RunAllTests(allResults);

        PrintDetectionSummary(allResults);

        cout << "============================================================\n";
        cout << "  Original Author: Tobias Klein (www.trapkit.de)\n";
        cout << "  Extended by: Real Ursus (North Pole)\n";
        cout << "  Version 3.0 - Refactored for comprehensive detection\n";
        cout << "============================================================\n\n";

        return 0;
    }
    catch (const exception& e) {
        cerr << "\nFatal Error: " << e.what() << "\n\n";
        return 1;
    }
    catch (...) {
        cerr << "\nFatal Error: Unknown exception occurred\n\n";
        return 1;
    }
}

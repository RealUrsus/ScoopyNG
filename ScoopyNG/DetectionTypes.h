/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: DetectionTypes.h
 * Purpose: Common types, enums, and constants for virtualization detection
 */

#pragma once

#include <string>
#include <cstdint>

// ============================================================================
// Detection Result Types
// ============================================================================

enum class HypervisorType {
    None,           // No virtualization detected
    VMware,         // VMware Workstation/ESXi/Fusion
    HyperV,         // Microsoft Hyper-V
    VirtualBox,     // Oracle VirtualBox
    KVM,            // KVM (including Proxmox)
    QEMU,           // QEMU (including Proxmox)
    Xen,            // Xen hypervisor
    Parallels,      // Parallels Desktop
    Unknown         // Unknown hypervisor detected
};

enum class DetectionResult {
    Detected,       // Virtualization positively detected
    NotDetected,    // No virtualization detected
    Inconclusive,   // Test completed but results unclear
    Error           // Test failed or threw error
};

enum class ConfidenceLevel {
    Low,            // Weak indicator (single check)
    Medium,         // Moderate indicator (multiple checks)
    High,           // Strong indicator (definitive proof)
    VeryHigh        // Absolute certainty (hardware signature)
};

// ============================================================================
// Detection Test Result
// ============================================================================

struct TestResult {
    DetectionResult result;
    HypervisorType hypervisorType;
    ConfidenceLevel confidence;
    std::string testName;
    std::string details;
    uint32_t testId;

    TestResult()
        : result(DetectionResult::NotDetected)
        , hypervisorType(HypervisorType::None)
        , confidence(ConfidenceLevel::Low)
        , testId(0) {}

    TestResult(DetectionResult res, HypervisorType hvType, ConfidenceLevel conf,
        const std::string& name, const std::string& det, uint32_t id)
        : result(res)
        , hypervisorType(hvType)
        , confidence(conf)
        , testName(name)
        , details(det)
        , testId(id) {}

    bool IsDetected() const {
        return result == DetectionResult::Detected;
    }

    bool IsError() const {
        return result == DetectionResult::Error;
    }
};

// ============================================================================
// Hypervisor Constants
// ============================================================================

namespace HypervisorConstants {
    // VMware
    constexpr uint32_t VMWARE_MAGIC = 0x564D5868;  // 'VMXh'
    constexpr uint16_t VMWARE_PORT = 0x5658;        // 'VX'
    constexpr const char* VMWARE_CPUID = "VMwareVMware";

    // Known VMware MAC address prefixes
    constexpr uint8_t VMWARE_MAC_PREFIXES[][3] = {
        {0x00, 0x05, 0x69},  // VMware, Inc.
        {0x00, 0x0C, 0x29},  // VMware, Inc.
        {0x00, 0x1C, 0x14},  // VMware, Inc.
        {0x00, 0x50, 0x56}   // VMware, Inc.
    };

    // Hyper-V
    constexpr const char* HYPERV_CPUID = "Microsoft Hv";
    constexpr const char* HYPERV_REG_KEY = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters";
    constexpr const char* HYPERV_PHYS_HOST_KEY = "PhysicalHostNameFullyQualified";

    // VirtualBox
    constexpr const char* VBOX_CPUID = "VBoxVBoxVBox";
    constexpr const char* VBOX_REG_KEY = "SOFTWARE\\Oracle\\VirtualBox Guest Additions";
    constexpr uint8_t VBOX_MAC_PREFIX[] = {0x08, 0x00, 0x27};

    // KVM
    constexpr const char* KVM_CPUID = "KVMKVMKVM\0\0\0";

    // QEMU
    constexpr const char* QEMU_CPUID = "TCGTCGTCGTCG";

    // Xen
    constexpr const char* XEN_CPUID = "XenVMMXenVMM";

    // Parallels
    constexpr const char* PARALLELS_CPUID = " prl hyperv ";
}

// ============================================================================
// Hypervisor Name Helper
// ============================================================================

inline const char* GetHypervisorName(HypervisorType type) {
    switch (type) {
    case HypervisorType::VMware: return "VMware";
    case HypervisorType::HyperV: return "Microsoft Hyper-V";
    case HypervisorType::VirtualBox: return "Oracle VirtualBox";
    case HypervisorType::KVM: return "KVM";
    case HypervisorType::QEMU: return "QEMU";
    case HypervisorType::Xen: return "Xen";
    case HypervisorType::Parallels: return "Parallels";
    case HypervisorType::Unknown: return "Unknown Hypervisor";
    default: return "None";
    }
}

inline const char* GetConfidenceName(ConfidenceLevel level) {
    switch (level) {
    case ConfidenceLevel::VeryHigh: return "Very High";
    case ConfidenceLevel::High: return "High";
    case ConfidenceLevel::Medium: return "Medium";
    case ConfidenceLevel::Low: return "Low";
    default: return "Unknown";
    }
}

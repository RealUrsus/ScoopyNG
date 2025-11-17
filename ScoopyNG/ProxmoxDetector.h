/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: ProxmoxDetector.h
 * Purpose: Proxmox/KVM/QEMU specific detection tests
 */

#pragma once

#include "IDetectionTest.h"
#include "DetectionTypes.h"
#include "Helpers.h"
#include <intrin.h>

// ============================================================================
// Proxmox/KVM/QEMU Detection Tests
// ============================================================================

// Test: KVM CPUID Detection
DECLARE_DETECTION_TEST(KvmCpuidTest, "KVM CPUID Detection",
    "Detects KVM via CPUID hypervisor leaf", 400, HypervisorType::KVM);

// Test: QEMU CPUID Detection
DECLARE_DETECTION_TEST(QemuCpuidTest, "QEMU CPUID Detection",
    "Detects QEMU via CPUID hypervisor leaf", 401, HypervisorType::QEMU);

// Test: QEMU WMI/BIOS Check
DECLARE_DETECTION_TEST(QemuBiosTest, "QEMU BIOS Check",
    "Checks BIOS for QEMU and SeaBIOS signatures", 402, HypervisorType::QEMU);

// Test: QEMU System Manufacturer
DECLARE_DETECTION_TEST(QemuWmiTest, "QEMU WMI Check",
    "Checks Win32_ComputerSystem for QEMU manufacturer", 403, HypervisorType::QEMU);

// Test: QEMU Devices Check
DECLARE_DETECTION_TEST(QemuDevicesTest, "QEMU Devices Check",
    "Checks for QEMU virtual devices (virtio, qemu)", 404, HypervisorType::QEMU);

// Test: QEMU Drivers Check
DECLARE_DETECTION_TEST(QemuDriversTest, "QEMU Drivers Check",
    "Checks for QEMU/virtio drivers", 405, HypervisorType::QEMU);

// Test: QEMU PCI Devices
DECLARE_DETECTION_TEST(QemuPciTest, "QEMU PCI Devices Check",
    "Checks for QEMU PCI device identifiers", 406, HypervisorType::QEMU);

// Test: QEMU Registry Check
DECLARE_DETECTION_TEST(QemuRegistryTest, "QEMU Registry Check",
    "Checks registry for QEMU/virtio entries", 407, HypervisorType::QEMU);

// Test: QEMU Disk Information
DECLARE_DETECTION_TEST(QemuDiskTest, "QEMU Disk Check",
    "Checks disk model for QEMU HARDDISK signature", 408, HypervisorType::QEMU);

// Test: QEMU Network Adapters
DECLARE_DETECTION_TEST(QemuNetworkTest, "QEMU Network Check",
    "Checks for Red Hat VirtIO Ethernet Adapter", 409, HypervisorType::QEMU);

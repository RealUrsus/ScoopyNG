/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: VirtualBoxDetector.h
 * Purpose: Oracle VirtualBox specific detection tests
 */

#pragma once

#include "IDetectionTest.h"
#include "DetectionTypes.h"
#include "Helpers.h"
#include <intrin.h>

// ============================================================================
// VirtualBox Detection Tests
// ============================================================================

// Test: VirtualBox CPUID Detection
DECLARE_DETECTION_TEST(VBoxCpuidTest, "VirtualBox CPUID Detection",
    "Detects VirtualBox via CPUID hypervisor leaf", 300, HypervisorType::VirtualBox);

// Test: VirtualBox Registry Check
DECLARE_DETECTION_TEST(VBoxRegistryTest, "VirtualBox Registry Check",
    "Checks for VirtualBox Guest Additions in registry", 301, HypervisorType::VirtualBox);

// Test: VirtualBox WMI Check
DECLARE_DETECTION_TEST(VBoxWmiTest, "VirtualBox WMI Check",
    "Checks BIOS and system info for VirtualBox signatures", 302, HypervisorType::VirtualBox);

// Test: VirtualBox BIOS Check
DECLARE_DETECTION_TEST(VBoxBiosTest, "VirtualBox BIOS Check",
    "Checks BIOS version and serial for VBOX signatures", 303, HypervisorType::VirtualBox);

// Test: VirtualBox MAC Address
DECLARE_DETECTION_TEST(VBoxMacTest, "VirtualBox MAC Address Check",
    "Checks network adapter MAC addresses for VirtualBox prefix (08:00:27)", 304, HypervisorType::VirtualBox);

// Test: VirtualBox Drivers Check
DECLARE_DETECTION_TEST(VBoxDriversTest, "VirtualBox Drivers Check",
    "Checks for VirtualBox drivers (VBoxGuest, VBoxMouse, VBoxVideo)", 305, HypervisorType::VirtualBox);

// Test: VirtualBox Files Check
DECLARE_DETECTION_TEST(VBoxFilesTest, "VirtualBox Files Check",
    "Checks for VirtualBox Guest Additions files", 306, HypervisorType::VirtualBox);

// Test: VirtualBox Processes Check
DECLARE_DETECTION_TEST(VBoxProcessTest, "VirtualBox Process Check",
    "Checks for VirtualBox processes (VBoxService, VBoxTray)", 307, HypervisorType::VirtualBox);

// Test: VirtualBox Devices Check
DECLARE_DETECTION_TEST(VBoxDevicesTest, "VirtualBox Devices Check",
    "Checks for VirtualBox PCI devices", 308, HypervisorType::VirtualBox);

// Test: VirtualBox ACPI Tables
DECLARE_DETECTION_TEST(VBoxAcpiTest, "VirtualBox ACPI Check",
    "Checks ACPI tables for VirtualBox signatures", 309, HypervisorType::VirtualBox);

// Test: VirtualBox System Firmware
DECLARE_DETECTION_TEST(VBoxFirmwareTest, "VirtualBox Firmware Check",
    "Checks system firmware tables for VBOX strings", 310, HypervisorType::VirtualBox);

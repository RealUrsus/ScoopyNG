/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: HyperVDetector.h
 * Purpose: Microsoft Hyper-V specific detection tests
 */

#pragma once

#include "IDetectionTest.h"
#include "DetectionTypes.h"
#include "Helpers.h"
#include <intrin.h>

// ============================================================================
// Hyper-V Detection Tests
// ============================================================================

// Test: Hyper-V CPUID Detection
DECLARE_DETECTION_TEST(HyperVCpuidTest, "Hyper-V CPUID Detection",
    "Detects Hyper-V via CPUID hypervisor leaf", 200, HypervisorType::HyperV);

// Test: Hyper-V Registry Check
DECLARE_DETECTION_TEST(HyperVRegistryTest, "Hyper-V Registry Check",
    "Checks for Hyper-V guest parameters in registry", 201, HypervisorType::HyperV);

// Test: Hyper-V WMI Check
DECLARE_DETECTION_TEST(HyperVWmiTest, "Hyper-V WMI Check",
    "Checks Win32_ComputerSystem Model for Hyper-V", 202, HypervisorType::HyperV);

// Test: Hyper-V BIOS Check
DECLARE_DETECTION_TEST(HyperVBiosTest, "Hyper-V BIOS Check",
    "Checks BIOS manufacturer for Microsoft Corporation", 203, HypervisorType::HyperV);

// Test: Hyper-V Drivers Check
DECLARE_DETECTION_TEST(HyperVDriversTest, "Hyper-V Drivers Check",
    "Checks for Hyper-V specific drivers (vmbus, storvsc, netvsc)", 204, HypervisorType::HyperV);

// Test: Hyper-V Services Check
DECLARE_DETECTION_TEST(HyperVServicesTest, "Hyper-V Services Check",
    "Checks for Hyper-V guest services", 205, HypervisorType::HyperV);

// Test: Hyper-V Integration Services
DECLARE_DETECTION_TEST(HyperVIntegrationTest, "Hyper-V Integration Services Check",
    "Checks for Hyper-V Integration Services files", 206, HypervisorType::HyperV);

// Test: Hyper-V Devices Check
DECLARE_DETECTION_TEST(HyperVDevicesTest, "Hyper-V Devices Check",
    "Checks for Hyper-V virtual devices in system", 207, HypervisorType::HyperV);

// Test: Hyper-V Time Source
DECLARE_DETECTION_TEST(HyperVTimeSourceTest, "Hyper-V Time Source Check",
    "Checks if Hyper-V is the VM time synchronization source", 208, HypervisorType::HyperV);

// Test: Hyper-V Generation Check
DECLARE_DETECTION_TEST(HyperVGenerationTest, "Hyper-V VM Generation Check",
    "Detects Hyper-V Generation 1 vs Generation 2 VM", 209, HypervisorType::HyperV);

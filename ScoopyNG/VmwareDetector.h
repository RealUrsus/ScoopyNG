/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: VmwareDetector.h
 * Purpose: VMware-specific detection tests
 */

#pragma once

#include "IDetectionTest.h"
#include "DetectionTypes.h"
#include "Helpers.h"
#include <intrin.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")

// External assembly functions for x64
#ifdef _M_X64
extern "C" {
    uint64_t GetIdtBase();
    uint64_t GetLdtBase();
    uint64_t GetGdtBase();
    uint64_t GetTaskRegister();
    uint64_t VMwareGetVersion();
    uint64_t VMwareGetMemorySize();
}
#endif

// x86 inline assembly helpers
#ifdef _M_IX86
inline uint32_t GetIdtBase() {
    unsigned char idtr[6];
    __asm sidt idtr
    return *((uint32_t*)&idtr[2]);
}

inline uint32_t GetLdtBase() {
    unsigned char ldtr[5] = "\xef\xbe\xad\xde";
    __asm sldt ldtr
    return *((uint32_t*)&ldtr[0]);
}

inline uint32_t GetGdtBase() {
    unsigned char gdtr[6];
    __asm sgdt gdtr
    return *((uint32_t*)&gdtr[2]);
}

inline uint32_t GetTaskRegister() {
    unsigned char mem[4] = { 0, 0, 0, 0 };
    __asm str mem;
    return *((uint32_t*)mem);
}
#endif

// ============================================================================
// VMware Detection Tests
// ============================================================================

// Test: VMware CPUID Detection
DECLARE_DETECTION_TEST(VMwareCpuidTest, "VMware CPUID Detection",
    "Detects VMware via CPUID hypervisor leaf", 100, HypervisorType::VMware);

// Test: VMware IDT Base Check
DECLARE_DETECTION_TEST(VMwareIdtTest, "VMware IDT Base Check",
    "Checks Interrupt Descriptor Table base address", 101, HypervisorType::VMware);

// Test: VMware LDT Base Check
DECLARE_DETECTION_TEST(VMwareLdtTest, "VMware LDT Base Check",
    "Checks Local Descriptor Table base address", 102, HypervisorType::VMware);

// Test: VMware GDT Base Check
DECLARE_DETECTION_TEST(VMwareGdtTest, "VMware GDT Base Check",
    "Checks Global Descriptor Table base address", 103, HypervisorType::VMware);

// Test: VMware STR Check
DECLARE_DETECTION_TEST(VMwareStrTest, "VMware Task Register Check",
    "Checks Store Task Register value", 104, HypervisorType::VMware);

// Test: VMware I/O Port Version
DECLARE_DETECTION_TEST(VMwareIoPortVersionTest, "VMware I/O Port Version",
    "Queries VMware version via I/O backdoor port", 105, HypervisorType::VMware);

// Test: VMware I/O Port Memory
DECLARE_DETECTION_TEST(VMwareIoPortMemoryTest, "VMware I/O Port Memory",
    "Queries VMware memory size via I/O backdoor port", 106, HypervisorType::VMware);

// Test: VMware BIOS Serial
DECLARE_DETECTION_TEST(VMwareBiosTest, "VMware BIOS Serial Check",
    "Checks BIOS serial number for VMware signature", 107, HypervisorType::VMware);

// Test: VMware MAC Address
DECLARE_DETECTION_TEST(VMwareMacTest, "VMware MAC Address Check",
    "Checks network adapter MAC addresses", 108, HypervisorType::VMware);

// Test: VMware Registry
DECLARE_DETECTION_TEST(VMwareRegistryTest, "VMware Registry Check",
    "Checks for VMware-specific registry keys", 109, HypervisorType::VMware);

// Test: VMware Files
DECLARE_DETECTION_TEST(VMwareFilesTest, "VMware Files Check",
    "Checks for VMware-specific files and drivers", 110, HypervisorType::VMware);

// Test: VMware Processes
DECLARE_DETECTION_TEST(VMwareProcessTest, "VMware Process Check",
    "Checks for VMware-specific processes", 111, HypervisorType::VMware);

/* ScoopyNG - The VMware Detection Tool
 * Version v2.0 - Refactored for x64 support
 *
 * Original Author:  Tobias Klein, 2008 [ www.trapkit.de ]
 * Modified by: Real Ursus, 2016-2025 (North Pole)
 *
 * Changelog v2.0:
 * - Full x64 platform support (primary platform)
 * - Refactored detection methods with modern C++ practices
 * - Separated assembly code to external .asm file
 * - Fixed MAC address detection bug
 * - Improved error handling with RAII
 * - Better code organization and maintainability
 */

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <excpt.h>
#include <intrin.h>
#include <Wbemidl.h>

#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>

#include <comdef.h>
#include <comutil.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "IPHLPAPI.lib")

using namespace std;

// ============================================================================
// Constants and Configuration
// ============================================================================

constexpr bool DEBUG_MODE = false;
constexpr DWORD VMWARE_MAGIC = 0x564D5868;  // 'VMXh'
constexpr WORD VMWARE_PORT = 0x5658;        // 'VX'

// Known VMware MAC address prefixes (3 bytes)
constexpr BYTE VMWARE_MAC_PREFIXES[][3] = {
    {0x00, 0x05, 0x69},  // VMware, Inc.
    {0x00, 0x0C, 0x29},  // VMware, Inc.
    {0x00, 0x1C, 0x14},  // VMware, Inc.
    {0x00, 0x50, 0x56},  // VMware, Inc.
};

// ============================================================================
// External Assembly Functions (x64)
// ============================================================================

#ifdef _M_X64
extern "C" {
    UINT64 GetIdtBase();
    UINT64 GetLdtBase();
    UINT64 GetGdtBase();
    UINT64 GetTaskRegister();
    UINT64 VMwareGetVersion();
    UINT64 VMwareGetMemorySize();
    void SwitchToCodeSegment();
}
#endif

// ============================================================================
// Type Definitions
// ============================================================================

typedef LONG(NTAPI* NTSETLDTENTRIES)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);

enum class DetectionResult {
    Native,
    VMwareDetected,
    HypervisorDetected,
    Error
};

struct VMwareVersion {
    enum Type {
        Unknown = 0,
        Express = 1,
        ESX = 2,
        GSX = 3,
        Workstation = 4
    };
};

// ============================================================================
// RAII Helper Classes
// ============================================================================

class ComInitializer {
public:
    ComInitializer() {
        hResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hResult)) {
            throw runtime_error("Failed to initialize COM library");
        }

        hResult = CoInitializeSecurity(
            nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr
        );

        if (FAILED(hResult)) {
            CoUninitialize();
            throw runtime_error("Failed to initialize COM security");
        }
    }

    ~ComInitializer() {
        CoUninitialize();
    }

    ComInitializer(const ComInitializer&) = delete;
    ComInitializer& operator=(const ComInitializer&) = delete;

private:
    HRESULT hResult;
};

template<typename T>
class ComPtr {
public:
    ComPtr() : ptr(nullptr) {}
    ~ComPtr() { Release(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T** operator&() {
        Release();
        return &ptr;
    }

    T* operator->() const { return ptr; }
    T* Get() const { return ptr; }

    void Release() {
        if (ptr) {
            ptr->Release();
            ptr = nullptr;
        }
    }

private:
    T* ptr;
};

// ============================================================================
// x86 Inline Assembly Helpers (for backward compatibility)
// ============================================================================

#ifdef _M_IX86

unsigned long GetIdtBase() {
    unsigned char idtr[6];
    unsigned long idt = 0;
    __asm sidt idtr
    idt = *((unsigned long*)&idtr[2]);
    return idt;
}

unsigned long GetLdtBase() {
    unsigned char ldtr[5] = "\xef\xbe\xad\xde";
    unsigned long ldt = 0;
    __asm sldt ldtr
    ldt = *((unsigned long*)&ldtr[0]);
    return ldt;
}

unsigned long GetGdtBase() {
    unsigned char gdtr[6];
    unsigned long gdt = 0;
    __asm sgdt gdtr
    gdt = *((unsigned long*)&gdtr[2]);
    return gdt;
}

unsigned long GetTaskRegister() {
    unsigned char mem[4] = { 0, 0, 0, 0 };
    __asm str mem;
    return *((unsigned long*)mem);
}

#endif

// ============================================================================
// Detection Methods
// ============================================================================

class VMwareDetector {
public:
    // Test 0: CPUID Hypervisor Detection
    static DetectionResult TestCpuidHypervisor(string& details) {
        char hvVendor[13] = { 0 };
        int cpuInfo[4] = { -1 };

        __cpuid(cpuInfo, 1);

        // Check bit 31 of ECX (hypervisor present bit)
        if ((cpuInfo[2] >> 31) & 1) {
            // Hypervisor is present - get vendor string
            __cpuid(cpuInfo, 0x40000000);
            memcpy(hvVendor, cpuInfo + 1, 12);

            if (strcmp(hvVendor, "VMwareVMware") == 0) {
                details = "VMware hypervisor detected via CPUID";
                return DetectionResult::VMwareDetected;
            }
            else if (strcmp(hvVendor, "Microsoft Hv") == 0) {
                __cpuid(cpuInfo, 0x40000003);
                if (cpuInfo[1] & 1) {
                    details = "Hyper-V root partition detected";
                }
                else {
                    details = "Hyper-V child partition detected";
                }
                return DetectionResult::HypervisorDetected;
            }
            else {
                details = string("Generic hypervisor detected: ") + hvVendor;
                return DetectionResult::HypervisorDetected;
            }
        }

        details = "No hypervisor detected via CPUID";
        return DetectionResult::Native;
    }

    // Test 1: IDT Base Address Check
    static DetectionResult TestIdtBase(string& details) {
#if defined(_M_X64) || defined(_M_IX86)
        UINT_PTR idtBase = GetIdtBase();

        ostringstream oss;
        oss << "IDT base: 0x" << hex << uppercase << idtBase;
        details = oss.str();

#ifdef _M_X64
        // On x64, VMware typically uses high memory addresses
        if ((idtBase >> 40) == 0xFF) {
            return DetectionResult::VMwareDetected;
        }
#else
        // On x86, check if high byte is 0xFF
        if ((idtBase >> 24) == 0xFF) {
            return DetectionResult::VMwareDetected;
        }
#endif
        return DetectionResult::Native;
#else
        details = "Platform not supported";
        return DetectionResult::Error;
#endif
    }

    // Test 2: LDT Base Address Check
    static DetectionResult TestLdtBase(string& details) {
#if defined(_M_X64) || defined(_M_IX86)
        UINT_PTR ldtBase = GetLdtBase();

        ostringstream oss;
        oss << "LDT base: 0x" << hex << uppercase << ldtBase;
        details = oss.str();

        // On native systems, LDT is typically 0 or specific value
        // VMware modifies this value
        if (ldtBase != 0 && ldtBase != 0xDEADBEEF) {
            return DetectionResult::VMwareDetected;
        }

        return DetectionResult::Native;
#else
        details = "Platform not supported";
        return DetectionResult::Error;
#endif
    }

    // Test 3: GDT Base Address Check
    static DetectionResult TestGdtBase(string& details) {
#if defined(_M_X64) || defined(_M_IX86)
        UINT_PTR gdtBase = GetGdtBase();

        ostringstream oss;
        oss << "GDT base: 0x" << hex << uppercase << gdtBase;
        details = oss.str();

#ifdef _M_X64
        // On x64, check high bits for VMware signature
        if ((gdtBase >> 40) == 0xFF) {
            return DetectionResult::VMwareDetected;
        }
#else
        // On x86, check if high byte is 0xFF
        if ((gdtBase >> 24) == 0xFF) {
            return DetectionResult::VMwareDetected;
        }
#endif
        return DetectionResult::Native;
#else
        details = "Platform not supported";
        return DetectionResult::Error;
#endif
    }

    // Test 4: Store Task Register (STR)
    static DetectionResult TestTaskRegister(string& details) {
#if defined(_M_X64) || defined(_M_IX86)
        UINT_PTR taskReg = GetTaskRegister();

        ostringstream oss;
        oss << "Task Register: 0x" << hex << uppercase << setfill('0') << setw(4) << taskReg;
        details = oss.str();

        // VMware typically returns 0x4000 for STR
        if (taskReg == 0x4000) {
            return DetectionResult::VMwareDetected;
        }

        return DetectionResult::Native;
#else
        details = "Platform not supported";
        return DetectionResult::Error;
#endif
    }

    // Test 5: VMware I/O Port "Get Version" Command
    static DetectionResult TestVMwareVersion(string& details, int& version) {
#ifdef _M_X64
        __try {
            UINT64 magic = VMwareGetVersion();
            // Version is in the upper 32 bits
            DWORD versionType = (DWORD)(magic >> 32);

            if ((DWORD)magic == VMWARE_MAGIC) {
                version = versionType;
                ostringstream oss;
                oss << "VMware detected - Version: ";
                switch (versionType) {
                case VMwareVersion::Express: oss << "Express"; break;
                case VMwareVersion::ESX: oss << "ESX"; break;
                case VMwareVersion::GSX: oss << "GSX"; break;
                case VMwareVersion::Workstation: oss << "Workstation"; break;
                default: oss << "Unknown (" << versionType << ")"; break;
                }
                details = oss.str();
                return DetectionResult::VMwareDetected;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception expected on non-VMware systems
        }
#elif defined(_M_IX86)
        __try {
            DWORD magic = 0, versionType = 0;
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
                mov versionType, ecx
                pop edx
                pop ecx
                pop ebx
                pop eax
            }

            if (magic == VMWARE_MAGIC) {
                version = versionType;
                ostringstream oss;
                oss << "VMware detected - Version: ";
                switch (versionType) {
                case VMwareVersion::Express: oss << "Express"; break;
                case VMwareVersion::ESX: oss << "ESX"; break;
                case VMwareVersion::GSX: oss << "GSX"; break;
                case VMwareVersion::Workstation: oss << "Workstation"; break;
                default: oss << "Unknown (" << versionType << ")"; break;
                }
                details = oss.str();
                return DetectionResult::VMwareDetected;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception expected on non-VMware systems
        }
#endif
        details = "VMware I/O port not accessible";
        return DetectionResult::Native;
    }

    // Test 6: VMware I/O Port "Get Memory Size" Command
    static DetectionResult TestVMwareMemory(string& details) {
#ifdef _M_X64
        __try {
            UINT64 memSize = VMwareGetMemorySize();

            if (memSize > 0) {
                ostringstream oss;
                oss << "VMware memory size: " << dec << memSize << " MB";
                details = oss.str();
                return DetectionResult::VMwareDetected;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception expected on non-VMware systems
        }
#elif defined(_M_IX86)
        __try {
            DWORD memSize = 0;
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
                ostringstream oss;
                oss << "VMware memory size: " << dec << memSize << " MB";
                details = oss.str();
                return DetectionResult::VMwareDetected;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception expected on non-VMware systems
        }
#endif
        details = "VMware memory query failed";
        return DetectionResult::Native;
    }

    // Test 7: VMware Emulation Mode Detection
    static int DetectEmulationMode(LPEXCEPTION_POINTERS lpep) {
#ifdef _M_X64
        UINT_PTR endUserMode = 0x00007FFFFFFFFFFF;  // x64 user mode boundary
#else
        UINT_PTR endUserMode = (*(UINT_PTR*)0x7FFE02B4);  // x86 user mode boundary
#endif

        if ((UINT_PTR)(lpep->ExceptionRecord->ExceptionAddress) > endUserMode) {
            cout << "Result  : VMware detected (emulation mode)" << endl << endl;
            return EXCEPTION_EXECUTE_HANDLER;
        }

        cout << "Result  : Native OS or VMware with acceleration" << endl << endl;
        return EXCEPTION_EXECUTE_HANDLER;
    }

    static DetectionResult TestEmulationMode(string& details) {
        // This test is complex and platform-specific
        // For now, we'll implement a simplified version
        details = "Emulation mode test - requires specific setup";

#if defined(_M_IX86) || defined(_M_X64)
        NTSETLDTENTRIES ZwSetLdtEntries;
        ZwSetLdtEntries = (NTSETLDTENTRIES)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "ZwSetLdtEntries");

        if (!ZwSetLdtEntries) {
            details = "ZwSetLdtEntries not available";
            return DetectionResult::Error;
        }

        // Note: This test requires careful implementation and may not work
        // reliably on modern systems. Marked for future enhancement.
        details = "Test requires elevation and may be unreliable on modern systems";
        return DetectionResult::Native;
#else
        return DetectionResult::Error;
#endif
    }

    // Test 8: Virtual BIOS DMI Information
    static DetectionResult TestBiosDmi(string& details) {
        try {
            ComInitializer comInit;

            ComPtr<IWbemLocator> pLocator;
            HRESULT hr = CoCreateInstance(
                CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&pLocator);

            if (FAILED(hr)) {
                details = "Failed to create WMI locator";
                return DetectionResult::Error;
            }

            ComPtr<IWbemServices> pServices;
            hr = pLocator->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"),
                nullptr, nullptr, 0, 0, 0, 0, &pServices);

            if (FAILED(hr)) {
                details = "Failed to connect to WMI";
                return DetectionResult::Error;
            }

            hr = CoSetProxyBlanket(
                pServices.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);

            if (FAILED(hr)) {
                details = "Failed to set proxy blanket";
                return DetectionResult::Error;
            }

            ComPtr<IEnumWbemClassObject> pEnumerator;
            hr = pServices->ExecQuery(
                bstr_t("WQL"),
                bstr_t("SELECT SerialNumber FROM Win32_BIOS"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator);

            if (FAILED(hr)) {
                details = "WMI query failed";
                return DetectionResult::Error;
            }

            ComPtr<IWbemClassObject> pClassObj;
            ULONG uReturn = 0;

            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObj, &uReturn);
            if (uReturn == 0) {
                details = "No BIOS information found";
                return DetectionResult::Error;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pClassObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);

            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                char* serialNumber = _com_util::ConvertBSTRToString(vtProp.bstrVal);

                if (serialNumber) {
                    if (strncmp(serialNumber, "VMware-", 7) == 0 ||
                        strncmp(serialNumber, "VMW", 3) == 0) {
                        details = string("VMware BIOS serial: ") + serialNumber;
                        delete[] serialNumber;
                        VariantClear(&vtProp);
                        return DetectionResult::VMwareDetected;
                    }
                    delete[] serialNumber;
                }
            }

            VariantClear(&vtProp);
            details = "BIOS check complete - no VMware signature";
            return DetectionResult::Native;
        }
        catch (const exception& e) {
            details = string("Exception: ") + e.what();
            return DetectionResult::Error;
        }
    }

    // Test 9: Virtual Network Adapter MAC Address Check
    static DetectionResult TestMacAddress(string& details) {
        ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
        PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
        PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
        bool vmwareDetected = false;
        vector<string> adapterDetails;

        // Allocate initial buffer
        pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, outBufLen);
        if (!pAddresses) {
            details = "Memory allocation failed";
            return DetectionResult::Error;
        }

        // Get adapter addresses (resize if needed)
        DWORD result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        if (result == ERROR_BUFFER_OVERFLOW) {
            HeapFree(GetProcessHeap(), 0, pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), 0, outBufLen);
            if (!pAddresses) {
                details = "Memory allocation failed";
                return DetectionResult::Error;
            }
            result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        }

        if (result != NO_ERROR) {
            HeapFree(GetProcessHeap(), 0, pAddresses);
            details = "GetAdaptersAddresses failed";
            return DetectionResult::Error;
        }

        // Enumerate adapters
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->PhysicalAddressLength >= 3) {
                // Check against known VMware MAC prefixes
                for (const auto& prefix : VMWARE_MAC_PREFIXES) {
                    if (memcmp(pCurrAddresses->PhysicalAddress, prefix, 3) == 0) {
                        vmwareDetected = true;

                        // Format MAC address
                        ostringstream oss;
                        oss << "VMware adapter found: ";
                        for (UINT i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
                            if (i > 0) oss << "-";
                            oss << hex << uppercase << setfill('0') << setw(2)
                                << (int)pCurrAddresses->PhysicalAddress[i];
                        }
                        adapterDetails.push_back(oss.str());
                        break;
                    }
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }

        HeapFree(GetProcessHeap(), 0, pAddresses);

        if (vmwareDetected) {
            ostringstream oss;
            for (const auto& detail : adapterDetails) {
                oss << detail << "; ";
            }
            details = oss.str();
            return DetectionResult::VMwareDetected;
        }

        details = "No VMware network adapters detected";
        return DetectionResult::Native;
    }
};

// ============================================================================
// Test Execution Functions
// ============================================================================

void PrintTestHeader(int testNum, const string& testName) {
    cout << "\n[+] Test " << testNum << ": " << testName << endl;
}

void PrintTestResult(DetectionResult result, const string& details) {
    cout << "Details : " << details << endl;
    cout << "Result  : ";

    switch (result) {
    case DetectionResult::VMwareDetected:
        cout << "VMware detected" << endl;
        break;
    case DetectionResult::HypervisorDetected:
        cout << "Hypervisor detected (non-VMware)" << endl;
        break;
    case DetectionResult::Native:
        cout << "Native OS" << endl;
        break;
    case DetectionResult::Error:
        cout << "Test error" << endl;
        break;
    }
    cout << endl;
}

void RunAllTests() {
    string details;
    int version = 0;

    // Test 0: CPUID
    PrintTestHeader(0, "CPUID Hypervisor Detection");
    PrintTestResult(VMwareDetector::TestCpuidHypervisor(details), details);

    // Test 1: IDT
    PrintTestHeader(1, "Interrupt Descriptor Table (IDT) Base");
    PrintTestResult(VMwareDetector::TestIdtBase(details), details);

    // Test 2: LDT
    PrintTestHeader(2, "Local Descriptor Table (LDT) Base");
    PrintTestResult(VMwareDetector::TestLdtBase(details), details);

    // Test 3: GDT
    PrintTestHeader(3, "Global Descriptor Table (GDT) Base");
    PrintTestResult(VMwareDetector::TestGdtBase(details), details);

    // Test 4: STR
    PrintTestHeader(4, "Store Task Register (STR)");
    PrintTestResult(VMwareDetector::TestTaskRegister(details), details);

    // Test 5: VMware Version
    PrintTestHeader(5, "VMware I/O Port - Get Version");
    PrintTestResult(VMwareDetector::TestVMwareVersion(details, version), details);

    // Test 6: VMware Memory
    PrintTestHeader(6, "VMware I/O Port - Get Memory Size");
    PrintTestResult(VMwareDetector::TestVMwareMemory(details), details);

    // Test 7: Emulation Mode
    PrintTestHeader(7, "VMware Emulation Mode Detection");
    PrintTestResult(VMwareDetector::TestEmulationMode(details), details);

    // Test 8: BIOS DMI
    PrintTestHeader(8, "Virtual BIOS DMI Information");
    PrintTestResult(VMwareDetector::TestBiosDmi(details), details);

    // Test 9: MAC Address
    PrintTestHeader(9, "Virtual Network Adapter MAC Address");
    PrintTestResult(VMwareDetector::TestMacAddress(details), details);
}

void PrintSystemInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    cout << "Hardware Information:" << endl;
    cout << "  Number of processors: " << sysInfo.dwNumberOfProcessors << endl;
    cout << "  Processor type: " << sysInfo.dwProcessorType << endl;

#ifdef _M_X64
    cout << "  Architecture: x64 (64-bit)" << endl;
#elif defined(_M_IX86)
    cout << "  Architecture: x86 (32-bit)" << endl;
#elif defined(_M_ARM64)
    cout << "  Architecture: ARM64" << endl;
#else
    cout << "  Architecture: Unknown" << endl;
#endif

    cout << "  Page size: " << sysInfo.dwPageSize << " bytes" << endl;

    // Calculate uptime
    DWORD uptime = GetTickCount();
    unsigned int days = uptime / (24 * 60 * 60 * 1000);
    uptime %= (24 * 60 * 60 * 1000);
    unsigned int hours = uptime / (60 * 60 * 1000);
    uptime %= (60 * 60 * 1000);
    unsigned int minutes = uptime / (60 * 1000);
    uptime %= (60 * 1000);
    unsigned int seconds = uptime / 1000;

    cout << "  System uptime: " << days << " days, " << hours << " hours, "
        << minutes << " minutes, " << seconds << " seconds" << endl;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    cout << "\n========================================================" << endl;
    cout << "  ScoopyNG - The VMware Detection Tool" << endl;
    cout << "  Version 2.0 - x64 Refactored Edition" << endl;
    cout << "========================================================\n" << endl;

    PrintSystemInfo();
    RunAllTests();

    cout << "========================================================" << endl;
    cout << "  Original Author: Tobias Klein (www.trapkit.de)" << endl;
    cout << "  Extended by: Real Ursus (North Pole)" << endl;
    cout << "  Refactored for x64: 2025" << endl;
    cout << "========================================================\n" << endl;

    return 0;
}

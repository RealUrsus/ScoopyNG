/* ScoopyNG - Multi-Platform Virtualization Detection Tool
 * Version v3.0 - Comprehensive Hypervisor Detection
 *
 * File: Helpers.h
 * Purpose: Utility classes and helper functions
 */

#pragma once

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")

// ============================================================================
// RAII COM Initializer
// ============================================================================

class ComInitializer {
public:
    ComInitializer() {
        hResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hResult)) {
            throw std::runtime_error("Failed to initialize COM library");
        }

        hResult = CoInitializeSecurity(
            nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, EOAC_NONE, nullptr
        );

        if (FAILED(hResult) && hResult != RPC_E_TOO_LATE) {
            CoUninitialize();
            throw std::runtime_error("Failed to initialize COM security");
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

// ============================================================================
// RAII COM Smart Pointer
// ============================================================================

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
// RAII Registry Key Wrapper
// ============================================================================

class RegistryKey {
public:
    RegistryKey() : hKey(nullptr) {}

    ~RegistryKey() {
        Close();
    }

    bool Open(HKEY hRootKey, const std::string& subKey, REGSAM samDesired = KEY_READ) {
        Close();
        LONG result = RegOpenKeyExA(hRootKey, subKey.c_str(), 0, samDesired, &hKey);
        return result == ERROR_SUCCESS;
    }

    bool Open(HKEY hRootKey, const std::wstring& subKey, REGSAM samDesired = KEY_READ) {
        Close();
        LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, samDesired, &hKey);
        return result == ERROR_SUCCESS;
    }

    void Close() {
        if (hKey) {
            RegCloseKey(hKey);
            hKey = nullptr;
        }
    }

    bool QueryStringValue(const std::string& valueName, std::string& value) {
        if (!hKey) return false;

        char buffer[512];
        DWORD bufferSize = sizeof(buffer);
        DWORD type;

        LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type,
            reinterpret_cast<LPBYTE>(buffer), &bufferSize);

        if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            value = std::string(buffer);
            return true;
        }

        return false;
    }

    bool QueryDwordValue(const std::string& valueName, DWORD& value) {
        if (!hKey) return false;

        DWORD bufferSize = sizeof(DWORD);
        DWORD type;

        LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type,
            reinterpret_cast<LPBYTE>(&value), &bufferSize);

        return (result == ERROR_SUCCESS && type == REG_DWORD);
    }

    bool ValueExists(const std::string& valueName) {
        if (!hKey) return false;
        return RegQueryValueExA(hKey, valueName.c_str(), nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
    }

    bool KeyExists(HKEY hRootKey, const std::string& subKey) {
        HKEY testKey;
        LONG result = RegOpenKeyExA(hRootKey, subKey.c_str(), 0, KEY_READ, &testKey);
        if (result == ERROR_SUCCESS) {
            RegCloseKey(testKey);
            return true;
        }
        return false;
    }

    operator bool() const {
        return hKey != nullptr;
    }

private:
    HKEY hKey;
};

// ============================================================================
// WMI Query Helper
// ============================================================================

class WmiQuery {
public:
    WmiQuery() : initialized(false) {}

    bool Initialize() {
        try {
            comInit = std::make_unique<ComInitializer>();

            HRESULT hr = CoCreateInstance(
                CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&pLocator);

            if (FAILED(hr)) return false;

            hr = pLocator->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"),
                nullptr, nullptr, 0, 0, 0, 0, &pServices);

            if (FAILED(hr)) return false;

            hr = CoSetProxyBlanket(
                pServices.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);

            if (FAILED(hr)) return false;

            initialized = true;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool QueryString(const std::wstring& query, const std::wstring& property, std::string& result) {
        if (!initialized) return false;

        try {
            ComPtr<IEnumWbemClassObject> pEnumerator;
            HRESULT hr = pServices->ExecQuery(
                bstr_t("WQL"),
                bstr_t(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator);

            if (FAILED(hr)) return false;

            ComPtr<IWbemClassObject> pClassObj;
            ULONG uReturn = 0;

            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObj, &uReturn);
            if (uReturn == 0) return false;

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pClassObj->Get(property.c_str(), 0, &vtProp, 0, 0);

            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                char* str = _com_util::ConvertBSTRToString(vtProp.bstrVal);
                if (str) {
                    result = std::string(str);
                    delete[] str;
                    VariantClear(&vtProp);
                    return true;
                }
            }

            VariantClear(&vtProp);
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool QueryAll(const std::wstring& query, const std::wstring& property, std::vector<std::string>& results) {
        if (!initialized) return false;

        try {
            ComPtr<IEnumWbemClassObject> pEnumerator;
            HRESULT hr = pServices->ExecQuery(
                bstr_t("WQL"),
                bstr_t(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator);

            if (FAILED(hr)) return false;

            ComPtr<IWbemClassObject> pClassObj;
            ULONG uReturn = 0;

            while (pEnumerator) {
                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObj, &uReturn);
                if (uReturn == 0) break;

                VARIANT vtProp;
                VariantInit(&vtProp);
                hr = pClassObj->Get(property.c_str(), 0, &vtProp, 0, 0);

                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                    char* str = _com_util::ConvertBSTRToString(vtProp.bstrVal);
                    if (str) {
                        results.push_back(std::string(str));
                        delete[] str;
                    }
                }

                VariantClear(&vtProp);
                pClassObj.Release();
            }

            return !results.empty();
        }
        catch (...) {
            return false;
        }
    }

private:
    std::unique_ptr<ComInitializer> comInit;
    ComPtr<IWbemLocator> pLocator;
    ComPtr<IWbemServices> pServices;
    bool initialized;
};

// ============================================================================
// String Utilities
// ============================================================================

namespace StringUtils {
    inline std::string ToLower(const std::string& str) {
        std::string result = str;
        for (char& c : result) {
            c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        }
        return result;
    }

    inline bool Contains(const std::string& haystack, const std::string& needle) {
        return haystack.find(needle) != std::string::npos;
    }

    inline bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle) {
        return ToLower(haystack).find(ToLower(needle)) != std::string::npos;
    }

    inline std::string FormatHex(uint64_t value, int width = 0) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase;
        if (width > 0) {
            oss << std::setfill('0') << std::setw(width);
        }
        oss << value;
        return oss.str();
    }

    inline std::string FormatMacAddress(const uint8_t* mac, size_t length) {
        std::ostringstream oss;
        for (size_t i = 0; i < length; i++) {
            if (i > 0) oss << "-";
            oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                << static_cast<int>(mac[i]);
        }
        return oss.str();
    }
}

// ============================================================================
// File System Utilities
// ============================================================================

namespace FileUtils {
    inline bool FileExists(const std::string& path) {
        DWORD attrib = GetFileAttributesA(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    inline bool DirectoryExists(const std::string& path) {
        DWORD attrib = GetFileAttributesA(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    inline bool DriverExists(const std::string& driverName) {
        std::string path = "\\\\.\\" + driverName;
        HANDLE hDevice = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);

        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return true;
        }

        return false;
    }
}

// ============================================================================
// Process Utilities
// ============================================================================

namespace ProcessUtils {
    inline bool IsProcessRunning(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        bool found = false;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string exeFile = pe32.szExeFile;
                if (StringUtils::ContainsIgnoreCase(exeFile, processName)) {
                    found = true;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return found;
    }
}

// ============================================================================
// Service Utilities
// ============================================================================

namespace ServiceUtils {
    inline bool ServiceExists(const std::string& serviceName) {
        SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (service) {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            return true;
        }

        CloseServiceHandle(scManager);
        return false;
    }

    inline bool IsServiceRunning(const std::string& serviceName) {
        SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!scManager) return false;

        SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }

        SERVICE_STATUS status;
        bool running = false;
        if (QueryServiceStatus(service, &status)) {
            running = (status.dwCurrentState == SERVICE_RUNNING);
        }

        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return running;
    }
}

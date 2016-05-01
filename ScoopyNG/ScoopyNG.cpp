/* ScoopyNG - The VMware detection tool
* Version v1.1
*
* Author:  Tobias Klein, 2008 [ www.trapkit.de ]
* Modified by: Real Ursus, 2016  (North Pole)
*/
#include <stdio.h>
#include <windows.h>
#include <excpt.h>
#include <intrin.h>
#include <iostream>
#include <comdef.h>
#include <comutil.h>
#include <Wbemidl.h>

using namespace std;

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

#define DEBUG	0
#define _WIN32_DCOM
#define EndUserModeAddress (*(UINT_PTR*)0x7FFE02B4)

typedef LONG(NTAPI *NTSETLDTENTRIES)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);


BSTR GetBIOS()
{
	HRESULT hres;
	BSTR SerialNumber{NULL};

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
		exit(EXIT_FAILURE);
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
		);


	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
		CoUninitialize();
		exit(EXIT_FAILURE);
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator *pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
		CoUninitialize();
		exit(EXIT_FAILURE);
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices *pSvc = NULL;

	// Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
		);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x" << hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		exit(EXIT_FAILURE);
	}

#if DEBUG == 1
	cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;
#endif

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
		);

	if (FAILED(hres))
	{
		cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		exit(EXIT_FAILURE);
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_BIOS"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		cout << "Query for operating system name failed." << " Error code = 0x" << hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		exit(EXIT_FAILURE);
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the SerialNumber property
		hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
		SerialNumber = vtProp.bstrVal;
		VariantClear(&vtProp);
		pclsObj->Release();
	}

	// Cleanup
	// ========
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();

	return SerialNumber;
}


unsigned long get_idt_base()
{
	unsigned char	idtr[6];
	unsigned long	idt = 0;

	_asm sidt idtr
	idt = *((unsigned long *)&idtr[2]);

	return (idt);
}

unsigned long get_ldtr_base()
{
	unsigned char   ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long   ldt = 0;

	_asm sldt ldtr
	ldt = *((unsigned long *)&ldtr[0]);

	return (ldt);
}

unsigned long get_gdt_base()
{
	unsigned char   gdtr[6];
	unsigned long   gdt = 0;

	_asm sgdt gdtr
	gdt = *((unsigned long *)&gdtr[2]);

	return (gdt);
}

// Based on https://blogs.msdn.microsoft.com/sqlosteam/2010/10/30/is-this-real-the-metaphysics-of-hardware-virtualization/
void test0() {
	char HVVendor[13];
	int CPUInfo[4] = { -1 };

	printf("[+] Test 0: CPUID\n");

	__cpuid(CPUInfo, 1);
	// check bit 31 of ECX
	if ((CPUInfo[2] >> 31) & 1)
	{
		// Hypervisor is present
		// Check CPUID leaf 0x40000000 EBX, ECX, EDX for Hypvervisor prod name
		__cpuid(CPUInfo, 0x40000000);
		memset(HVVendor, 0, sizeof(HVVendor));
		memcpy(HVVendor, CPUInfo + 1, 12);

		if (!strcmp(HVVendor, "Microsoft Hv"))
		{
			// Check CPUID leaf 0x40000003 bit 1 (CreatePartitions bit)
			__cpuid(CPUInfo, 0x40000003);
			if (CPUInfo[1] & 1)
			{
				printf("Result  : Running in a Hyper - V root partition\n\n");
			}
			else
			{
				printf("Result  : Running inside a VM in a Hyper - V child partition\n\n");
			}
		}
		else if (!strcmp(HVVendor, "VMwareVMware")) {
			printf("Result  : VMware detected\n\n");
		}
		else printf("Result  : Running inside a VM on a hypervisor\n\n");
	}
	else printf("Result  : Native OS\n\n");
}

void test1()
{
	unsigned int 	idt_base = 0;

	idt_base = get_idt_base();

	printf("[+] Test 1: IDT\n");
	printf("IDT base: 0x%x\n", idt_base);

	if ((idt_base >> 24) == 0xff) {
		printf("Result  : VMware detected\n\n");
		return;
	}

	else {
		printf("Result  : Native OS\n\n");
		return;
	}
}

void test2()
{
	unsigned int	ldt_base = 0;

	ldt_base = get_ldtr_base();

	printf("[+] Test 2: LDT\n");
	printf("LDT base: 0x%x\n", ldt_base);

	if (ldt_base == 0xdead0000) {
		printf("Result  : Native OS\n\n");
		return;
	}

	else {
		printf("Result  : VMware detected\n\n");
		return;
	}
}

void test3()
{
	unsigned int	gdt_base = 0;

	gdt_base = get_gdt_base();

	printf("[+] Test 3: GDT\n");
	printf("GDT base: 0x%x\n", gdt_base);

	if ((gdt_base >> 24) == 0xff) {
		printf("Result  : VMware detected\n\n");
		return;
	}

	else {
		printf("Result  : Native OS\n\n");
		return;
	}
}

// Alfredo Andrés Omella's (S21sec) STR technique
void test4()
{
	unsigned char	mem[4] = { 0, 0, 0, 0 };

	__asm str mem;

	printf("[+] Test 4: STR\n");
	printf("STR base: 0x%02x%02x%02x%02x\n", mem[0], mem[1], mem[2], mem[3]);

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
		printf("Result  : VMware detected\n\n");
	else
		printf("Result  : Native OS\n\n");
}

void test5()
{
	unsigned int	a, b;

	__try {
		__asm {
			push eax
			push ebx
			push ecx
			push edx

			// perform fingerprint
			mov eax, 'VMXh'	// VMware magic value (0x564D5868)
			mov ebx, 0;		// This can be any value except MAGIC
			mov ecx, 0Ah		// "CODE" to get the VMware Version
			mov dx, 'VX'		// special VMware I/O port (0x5658)

			in eax, dx			// special I/O cmd

			mov a, ebx			// data 
			mov b, ecx			// data	(eax gets also modified but will not be evaluated)

			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

#if DEBUG == 1
	printf("\n [ a=%x ; b=%d ]\n\n", a, b);
#endif

	printf("[+] Test 5: VMware \"get version\" command\n");

	if (a == 'VMXh') {		// is the value equal to the VMware magic value?
		printf("Result  : VMware detected\nVersion : ");
		if (b == 1)
			printf("Express\n\n");
		else if (b == 2)
			printf("ESX\n\n");
		else if (b == 3)
			printf("GSX\n\n");
		else if (b == 4)
			printf("Workstation\n\n");
		else
			printf("unknown version\n\n");
	}
	else
		printf("Result  : Native OS\n\n");
}

void test6()
{
	unsigned int	a = 0;

	__try {
		__asm {

			// save register values on the stack
			push eax
			push ebx
			push ecx
			push edx

			// perform fingerprint
			mov eax, 'VMXh'		// VMware magic value (0x564D5868)
			mov ecx, 14h		// get memory size command (0x14)
			mov dx, 'VX'		// special VMware I/O port (0x5658)

			in eax, dx			// special I/O cmd

			mov a, eax			// data 

								// restore register values from the stack
			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	printf("[+] Test 6: VMware \"get memory size\" command\n");

	if (a > 0)
		printf("Result  : VMware detected\n\n");
	else
		printf("Result  : Native OS\n\n");
}

int test7_detect(LPEXCEPTION_POINTERS lpep)
{
	printf("[+] Test 7: VMware emulation mode\n");

	if ((UINT_PTR)(lpep->ExceptionRecord->ExceptionAddress) > EndUserModeAddress)
		printf("Result  : VMware detected (emulation mode detected)\n\n");
	else
		printf("Result  : Native OS or VMware without emulation mode (enabled acceleration)\n\n");

	return (EXCEPTION_EXECUTE_HANDLER);
}

void __declspec(naked)
test7_switchcs()
{
	__asm {
		pop eax
		push 0x000F
		push eax
		retf
	}
}

// Derek Soeder's (eEye Digital Security) VMware emulation test
void test7()
{
	NTSETLDTENTRIES ZwSetLdtEntries;
	LDT_ENTRY csdesc;

	ZwSetLdtEntries = (NTSETLDTENTRIES)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwSetLdtEntries");

	memset(&csdesc, 0, sizeof(csdesc));

	csdesc.LimitLow = (WORD)(EndUserModeAddress >> 12);
	csdesc.HighWord.Bytes.Flags1 = 0xFA;
	csdesc.HighWord.Bytes.Flags2 = 0xC0 | ((EndUserModeAddress >> 28) & 0x0F);

	ZwSetLdtEntries(0x000F, ((DWORD*)&csdesc)[0], ((DWORD*)&csdesc)[1], 0, 0, 0);

	__try {
		test7_switchcs();
		__asm {
			or eax, -1
				jmp eax
		}
	}
	__except (test7_detect(GetExceptionInformation())) { }
}

void test8() 
{
	cout << "[+] Test 8: Virtual BIOS DMI information" << endl;

	char * SerialNumber = _com_util::ConvertBSTRToString(GetBIOS());

	if (!memcmp(SerialNumber, "VMware-", 7) || !memcmp(SerialNumber, "VMW", 3))	
		cout << "Result  : DMI contains VMware specific string: " << SerialNumber << "\n\n" << endl;
	else
		cout << "Result  : Native OS" << "\n\n"<< endl;


}


int main()
{
	printf("\n\n####################################################\n");
	printf("::       ScoopyNG - The VMware Detection Tool     ::\n");
	printf("::              Windows version v1.1              ::\n\n");


	SYSTEM_INFO siSysInfo;

	GetSystemInfo(&siSysInfo);

	printf("Hardware information: \n");
	printf("  Number of processors: %u\n", siSysInfo.dwNumberOfProcessors);	
	printf("  Processor type: %u\n", siSysInfo.dwProcessorType);
	printf("  Processor Revision: %u\n", siSysInfo.wProcessorRevision);
	printf("  Page size: %u\n\n", siSysInfo.dwPageSize);
	

	test0();
	test1();
	test2();
	test3();
	test4();
	test5();
	test6();
	test7();
	test8();

	printf("::    Author: Tobias Klein (www.trapkit.de)       ::\n");
	printf("::    Extended by: Real Ursus (North Pole)        ::\n");
	printf("####################################################\n\n");

	return 0;
}
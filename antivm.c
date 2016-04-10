#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <misc.h>
#include <dynimp.h>
#include <safe_procedures.h>
#include <Wbemcli.h>
#include "antivm.h"

#define VBOX_FAIL					"\xee\xfb\x15\x51\x37\xa9\xa2\x67\x39\x4b\x9e\x9f\xa3\x05\x5f\xf0\xde\x09\xa4\xa7" // "PCI\\VEN_80EE&DEV_CAFE"	-> unicode
#define IS_VMWARE					"\x72\x19\x78\xcf\x34\x89\x66\x34\xe1\x10\x2f\x21\xf1\x5c\x73\x96\x38\x9e\xa7\x69"  // VMware											
#define VMWARE_WHITELISTED			"\x83\xbe\x37\x16\x52\x97\x24\xc9\x73\xbe\x68\xbb\x0e\x46\x00\xa0\xc0\xf3\x74\x0d"  // VMware-aa aa aa aa aa aa aa aa

BOOL wmiexec_searchash(IWbemServices *pSvc, LPWSTR strQuery, LPWSTR strField, LPBYTE pSearchHash, LPVARIANT lpVar);
BOOL wmiexec_getprop(IWbemServices *pSvc, LPWSTR strQuery, LPWSTR strField, LPVARIANT lpVar);
VOID CalculateSHA1(__out PBYTE pSha1Buffer, __in PBYTE pBuffer, __in ULONG uBufflen);

BOOL anti_vmware()
{
	BOOL bVMWareFound = FALSE;
	IWbemLocator *pLoc = 0;
	IWbemServices *pSvc = 0;

	CoInitialize(NULL);
	if (CoCreateInstance(&(CLSID_WbemLocator), 0, CLSCTX_INPROC_SERVER, &(IID_IWbemLocator), (LPVOID *)&pLoc) != S_OK)
		return FALSE;
	if (!pLoc)
		return FALSE;

	WCHAR strRootCIM[] = { L'R', L'O', L'O', L'T', L'\\', L'C', L'I', L'M', L'V', L'2', L'\0' };
	BSTR bRootCIM = SysAllocString(strRootCIM);

	if (pLoc->lpVtbl->ConnectServer(pLoc, bRootCIM, NULL, NULL, 0, 0, 0, 0, &pSvc) == WBEM_S_NO_ERROR)
	{
		if (CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE) == S_OK)
		{
			VARIANT vArg;
			VariantInit(&vArg);

			WCHAR strQuery[] = { L'S', L'E', L'L', L'E', L'C', L'T', L' ', L'*', L' ', L'F', L'R', L'O', L'M', L' ', L'W', L'i', L'n', L'3', L'2', L'_', L'B', L'i', L'o', L's', L'\0' };
			WCHAR strSerial[] = { L'S', L'e', L'r', L'i', L'a', L'l', L'N', L'u', L'm', L'b', L'e', L'r', L'\0' };
			if (wmiexec_getprop(pSvc, strQuery, strSerial, &vArg) && vArg.vt == VT_BSTR)
			{


				LPWSTR strSerial = _wcsdup(vArg.bstrVal);
				LPWSTR strend = wcschr(strSerial, '-');

				if (strend)
				{
					BYTE pSha1Buffer[20];
					*strend = L'\0';
					CalculateSHA1(pSha1Buffer, (LPBYTE)strSerial, wcslen(strSerial));

					if (!memcmp(pSha1Buffer, IS_VMWARE, 20))
					{

						*strend = L'-';
						strend = wcsrchr(strSerial, '-');

						if (strend) 
						{
							*strend = L'\0';

							SecureZeroMemory(pSha1Buffer, 20);
							CalculateSHA1(pSha1Buffer, (LPBYTE)strSerial, wcslen(strSerial));

							// negative check against sha1("VMware - aa aa aa aa aa aa aa aa")
							if (memcmp(pSha1Buffer, VMWARE_WHITELISTED, 20))
								bVMWareFound = TRUE;
						}

					}
				} // if (strend)

				if (strSerial)
					free(strSerial);

			}
			VariantClear(&vArg);
		}
	}

	if (pSvc)
		pSvc->lpVtbl->Release(pSvc);
	if (pLoc)
		pLoc->lpVtbl->Release(pLoc);

	return bVMWareFound;
}

BOOL anti_vbox()
{
	BOOL bVBoxFound = FALSE;
	IWbemLocator *pLoc = 0;
	IWbemServices *pSvc = 0;

	CoInitialize(NULL);
	if (CoCreateInstance(&(CLSID_WbemLocator), 0, CLSCTX_INPROC_SERVER, &(IID_IWbemLocator), (LPVOID *)&pLoc) != S_OK)
		return FALSE;
	if (!pLoc)
		return FALSE;

	WCHAR strRootCIM[] = { L'R', L'O', L'O', L'T', L'\\', L'C', L'I', L'M', L'V', L'2', L'\0' };
	BSTR bRootCIM = SysAllocString(strRootCIM);

	if (pLoc->lpVtbl->ConnectServer(pLoc, bRootCIM, NULL, NULL, 0, 0, 0, 0, &pSvc) == WBEM_S_NO_ERROR)
	{
		if (CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE) == S_OK)
		{
			VARIANT vArg;
			VariantInit(&vArg);

			WCHAR strQuery[] = { L'S', L'E', L'L', L'E', L'C', L'T', L' ', L'*', L' ', L'F', L'R', L'O', L'M', L' ', L'W', L'i', L'n', L'3', L'2', L'_', L'P', L'n', L'P', L'E', L'n', L't', L'i', L't', L'y', L'\0' };
			WCHAR strDeviceId[] = { L'D', L'e', L'v', L'i', L'c', L'e', L'I', L'd', L'\0' };
			if (wmiexec_searchash(pSvc, strQuery, strDeviceId, (LPBYTE)VBOX_FAIL, &vArg))
				bVBoxFound = TRUE;
			VariantClear(&vArg);
		}
	}

	if (pSvc)
		pSvc->lpVtbl->Release(pSvc);
	if (pLoc)
		pLoc->lpVtbl->Release(pLoc);

	return bVBoxFound;
}

BOOL anti_vm()
{
	BOOL vm_vmware = anti_vmware();
	BOOL vm_vbox = anti_vbox();

	if (vm_vbox || vm_vmware)
		return TRUE;
	
	return FALSE;
}

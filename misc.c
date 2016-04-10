#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Wbemcli.h>
#include <sha1.h>

#pragma comment (lib, "wbemuuid.lib")
#pragma comment (lib, "Ws2_32.lib")


VOID CalculateSHA1(__out PBYTE pSha1Buffer, __in PBYTE pBuffer, __in ULONG uBufflen)
{
	SHA1Context pSha1Context;

	SHA1Reset(&pSha1Context);
	SHA1Input(&pSha1Context, pBuffer, uBufflen);
	SHA1Result(&pSha1Context);

	for (ULONG x = 0; x<5; x++)
		((PULONG)pSha1Buffer)[x] = ntohl(pSha1Context.Message_Digest[x]);
}

BOOL wmiexec_getprop(IWbemServices *pSvc, LPWSTR strQuery, LPWSTR strField, LPVARIANT lpVar)
{
	BOOL bRet = FALSE;
	IEnumWbemClassObject *pEnum;

	BSTR bstrQuery = SysAllocString(strQuery);
	BSTR bstrField = SysAllocString(strField);

	WCHAR strWQL[] = { L'W', L'Q', L'L', L'\0' };
	BSTR bWQL = SysAllocString(strWQL);

	HRESULT hr = pSvc->lpVtbl->ExecQuery(pSvc, bWQL, bstrQuery, 0, NULL, &pEnum);
	if (hr == S_OK)
	{
		ULONG uRet;
		IWbemClassObject *apObj;
		hr = pEnum->lpVtbl->Next(pEnum, 5000, 1, &apObj, &uRet);
		if (hr == S_OK)
		{
			hr = apObj->lpVtbl->Get(apObj, bstrField, 0, lpVar, NULL, NULL);
			if (hr == WBEM_S_NO_ERROR)
				bRet = TRUE;

			apObj->lpVtbl->Release(apObj);
		}
		pEnum->lpVtbl->Release(pEnum);
	}

	SysFreeString(bstrQuery);
	SysFreeString(bstrField);
	SysFreeString(bWQL);

	return bRet;
}

BOOL wmiexec_searchash(IWbemServices *pSvc, LPWSTR strQuery, LPWSTR strField, LPBYTE pSearchHash, LPVARIANT lpVar)
{
	BOOL bFound = FALSE;
	IEnumWbemClassObject *pEnum;
	WCHAR strWQL[] = { L'W', L'Q', L'L', L'\0' };

	BSTR bWQL = SysAllocString(strWQL);
	BSTR bstrQuery = SysAllocString(strQuery);
	BSTR bstrField = SysAllocString(strField);

	HRESULT hr = pSvc->lpVtbl->ExecQuery(pSvc,bWQL, bstrQuery, 0, NULL, &pEnum);
	if (hr == S_OK)
	{
		ULONG uRet;
		IWbemClassObject *apObj;

		while (pEnum->lpVtbl->Next(pEnum, 5000, 1, &apObj, &uRet) == S_OK)
		{
			hr = apObj->lpVtbl->Get(apObj,bstrField, 0, lpVar, NULL, NULL);
			if (hr != WBEM_S_NO_ERROR || lpVar->vt != VT_BSTR)
				continue;

			BYTE pSha1Buffer[20];
			CalculateSHA1(pSha1Buffer, (LPBYTE)lpVar->bstrVal, 21 * sizeof(WCHAR));
			if (!memcmp(pSha1Buffer, pSearchHash, 20))
				bFound = TRUE;

			apObj->lpVtbl->Release(apObj);
		}

		pEnum->lpVtbl->Release(pEnum);
	}

	SysFreeString(bstrQuery);
	SysFreeString(bstrField);
	SysFreeString(bWQL);

	return bFound;
}
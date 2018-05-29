#pragma once

#include <stdio.h>
#include <windows.h>

#include "peconv.h"

class PeWrapper
{
public:
	PeWrapper(DWORD res_id, peconv::hooking_func_resolver *func_resolver)
		: resId(res_id), ready(false),
		malware(nullptr), vMalwareSize(0)
	{
		ready = initBot(func_resolver);
	}

	virtual ~PeWrapper()
	{
		peconv::free_pe_buffer(malware, vMalwareSize);
	}

	bool isReady() { return ready; }

	FARPROC getFunction(DWORD rva);
	LPVOID getBuffer(DWORD rva);

	bool redirectToLocalFunc(DWORD rva, FARPROC newFunc)
	{
		if (!is64) {
			peconv::redirect_to_local32((PBYTE)((ULONGLONG)malware + rva), (DWORD) newFunc);
		} else {
			peconv::redirect_to_local64((PBYTE)((ULONGLONG)malware + rva), (ULONGLONG) newFunc);
		}
		return true;
	}

	ULONGLONG getImgBase()
	{
		return (ULONGLONG) malware;
	}

	FARPROC getEntryPoint()
	{
		if (!malware) return nullptr;
		DWORD epRVA = peconv::get_entry_point_rva(malware);
		return (FARPROC) ((ULONGLONG)malware + epRVA);
	}

	bool replaceTarget(DWORD rva_from, ULONGLONG va_to);

protected:
	PeWrapper(DWORD res_id)
		: resId(res_id), ready(false), 
		malware(nullptr), vMalwareSize(0)
	{
	}

	virtual bool initBot(peconv::hooking_func_resolver *func_resolver)
	{
		if (!loadRes(func_resolver)) {
			return false;
		}
		is64 = peconv::is64bit(malware);
		return true;
	}

	bool loadRes(peconv::hooking_func_resolver *my_resolver = nullptr);
	virtual bool load(BYTE *raw_buffer, size_t raw_size, peconv::hooking_func_resolver *my_res = nullptr);

	bool is64;
	bool ready;
	DWORD resId;

	BYTE *malware;
	size_t vMalwareSize;
};

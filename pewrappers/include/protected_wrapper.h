#pragma once

#include <stdio.h>
#include <windows.h>

#include "pe_wrapper.h"
#include "peconv.h"

//#include "protect\protect.h"

class ProtectedWrapper : public PeWrapper
{
public:
	ProtectedWrapper(DWORD res_id, peconv::hooking_func_resolver *func_resolver, BYTE *_key, size_t _key_size)
		: PeWrapper(res_id),
		key(nullptr), keySize(0)
	{
		if (!setKey(_key, _key_size)) {
			return;
		}
		ready = initBot(func_resolver);
		//eraseKey();
	}
	
	void eraseKey()
	{
		if (!key) return;
		memset(key, 0, keySize);
		peconv::free_unaligned(key);
		key = nullptr;
	}

protected:
	virtual bool initBot(peconv::hooking_func_resolver *func_resolver)
	{
		//std::cout << "Init protected" << std::endl;
		if (!loadRes(func_resolver)) {
			return false;
		}
		is64 = peconv::is64bit(malware);
		return true;
	}

	virtual bool load(BYTE *raw_buffer, size_t raw_size, peconv::hooking_func_resolver *my_res = nullptr);
	BYTE* load_protected(BYTE *raw_buffer, size_t raw_size, size_t &decoded_size);

	bool setKey(BYTE *_key, size_t _key_size)
	{
		eraseKey();
		this->key = peconv::alloc_unaligned(_key_size);
		if (!key) return false;

		keySize = _key_size;
		memcpy(key, _key, keySize);
		return true;
	}
	
	size_t keySize;
	BYTE *key;
};
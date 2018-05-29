#pragma once

#include <Windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace protect {
	const size_t CHUNK_SIZE = 128;
	BOOL aes_crypt(IN BYTE *inbuf, IN const DWORD inputSize, OUT BYTE *outbuf, IN size_t buf_size, OUT size_t *out_size, IN const char* key_str, IN size_t key_len, IN bool isDecrypt);
};

#include <Windows.h>
#include "aes_crypt.h"

#include <iostream>

namespace protect {

	BOOL process_buffer(BYTE *inbuf, DWORD inputSize, BYTE *outbuf, size_t outBufSize, OUT size_t *processedSize, HCRYPTKEY hKey, bool isDecrypt)
	{
		if (processedSize != nullptr) {
			*processedSize = 0;
		}
		size_t processed_bytes = 0;
		size_t chunk_size = protect::CHUNK_SIZE;
		BYTE chunk[protect::CHUNK_SIZE] = { 0 };

		size_t chunks = inputSize / protect::CHUNK_SIZE;

		bool has_reminder = (inputSize % protect::CHUNK_SIZE) > 0;
		if (has_reminder) {
			chunks++;
		}

		BYTE *outptr = outbuf;
		for (size_t i = 0; i < chunks; i++) {
			BOOL isFinal = FALSE;
			BYTE *next_ptr = inbuf + (i * chunk_size);
			size_t rem_size = inputSize - (i * chunk_size);
			if (rem_size < chunk_size) {
				chunk_size = rem_size;
				std::cout << "Last chunk: " << chunk_size << std::endl;
				isFinal = TRUE;
			}
			memcpy(chunk, next_ptr, chunk_size);
			DWORD out_len = chunk_size;
			
			if (!isDecrypt) {
				if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, protect::CHUNK_SIZE)) {
					std::cout << "[-] CryptEncrypt failed: " << std::hex << GetLastError() << std::endl;
					return FALSE;
				}
			} else {
				if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
					std::cout << "[-] CryptDecrypt failed: " << std::hex << GetLastError() << std::endl;
					return FALSE;
				}
			}
			if ((processed_bytes + out_len) > outBufSize) {
				std::cerr << "Output buffer finished!" << std::endl;
				break;
			}
			memcpy(outptr, chunk, out_len);
			outptr += out_len;
			processed_bytes += out_len;

			memset(chunk, 0, protect::CHUNK_SIZE);
		}
		if (processedSize != nullptr) {
			*processedSize = processed_bytes;
		}
		return TRUE;
	}
};

BOOL protect::aes_crypt(BYTE *inbuf, DWORD inputSize, BYTE *outbuf, size_t outBufSize, OUT size_t *processedSize, const char* key_str, size_t key_len, bool isDecrypt)
{
	if (inbuf == NULL || outbuf == NULL) return FALSE;

	BOOL dwStatus = FALSE;

	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		dwStatus = GetLastError();
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
		dwStatus = GetLastError();
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	
	if (!CryptHashData(hHash, (BYTE*)key_str, key_len, 0)) {
		DWORD err = GetLastError();
		//DBGP(("CryptHashData Failed : %#x\n", err));
		return dwStatus;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0,&hKey)){
		dwStatus = GetLastError();
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	BOOL isOk = protect::process_buffer(inbuf, inputSize, outbuf, outBufSize, processedSize, hKey, isDecrypt);
	dwStatus = isOk;

	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	return dwStatus;
}


#include "protected_wrapper.h"

#include "protect\protect.h"

BYTE* ProtectedWrapper::load_protected(BYTE *enc_buf, size_t enc_size, size_t &out_size)
{
	BYTE *compressed_buf = peconv::alloc_aligned(enc_size, PAGE_READWRITE);
	if (!compressed_buf) {
		return nullptr;
	}
	size_t processed_len = 0;
	if (!protect::aes_crypt(enc_buf, enc_size, compressed_buf, enc_size, &processed_len, (const char*) key, keySize, true)) {
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}

	size_t decoded_size = processed_len * 2;
	BYTE *decoded_buf = peconv::alloc_aligned(decoded_size, PAGE_READWRITE);
	if (!decoded_buf) {
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}
	ULONG dec_size = 0;
	if (!protect::decompress_buffer((const char*) compressed_buf, processed_len, decoded_buf, decoded_size, &dec_size)) {
#ifdef _DEBUG
		std::cout << "Decompression failed!" << std::endl;
#endif
		peconv::free_aligned(compressed_buf);
		peconv::free_aligned(decoded_buf);
		return nullptr;
	}

	peconv::free_aligned(compressed_buf);

	out_size = size_t(dec_size);
	return decoded_buf;
}

bool ProtectedWrapper::load(BYTE *enc_buf, size_t enc_size, peconv::hooking_func_resolver *my_resolver)
{
	size_t decoded_size = 0;
	BYTE *decoded_buf = load_protected(enc_buf, enc_size, decoded_size);
#ifdef _DEBUG
	std::cout << "Protected load:" << std::endl;
#endif
	bool isOk = PeWrapper::load(decoded_buf, decoded_size, my_resolver);
	peconv::free_aligned(decoded_buf);
	return isOk;
}

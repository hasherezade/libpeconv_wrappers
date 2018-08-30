#include "protect.h"

#include "peconv.h"



BOOL test_compressed(BYTE *raw_pe, size_t raw_size, BYTE *compressed_buf, size_t compressed_size)
{
	const size_t test_buf_size = raw_size;
	BYTE *test_buf = peconv::alloc_unaligned(raw_size);
	if (!test_buf) {
		return FALSE;
	}
	ULONG out_size = raw_size;
	BOOL is_ok = protect::decompress_buffer((const char*)compressed_buf, compressed_size, test_buf, test_buf_size, &out_size);
	if (is_ok) {
		if (!memcmp(raw_pe, test_buf, raw_size) == 0) {
			is_ok = FALSE;
			std::cout << "[ERROR] Compressed vs uncompressed: not equal!" << std::endl;
		}
	}
#ifdef _DEBUG
	if (peconv::dump_to_file("compressed.bin", compressed_buf, compressed_size)) {
		std::cout << "Dumped compressed.bin!" << std::endl;
	}
	if (peconv::dump_to_file("uncompressed.bin", test_buf, raw_size)) {
		std::cout << "Dumped uncompressed.bin!" << std::endl;
	}
#endif
	peconv::free_unaligned(test_buf);
	return is_ok;
}

BOOL test_encrypted(BYTE *compressed_buf, size_t compressed_size, BYTE *encrypted_buf, size_t encrypted_size, const char *key, size_t key_size)
{
	const size_t test_buf_size = compressed_size + protect::CHUNK_SIZE;
	BYTE *test_buf = peconv::alloc_unaligned(test_buf_size);
	if (!test_buf) {
		return FALSE;
	}
	size_t out_size = test_buf_size;
	BOOL is_ok = protect::aes_crypt(encrypted_buf, encrypted_size, test_buf, test_buf_size, &out_size, key, key_size, true);
	if (is_ok) {
		if (memcmp(compressed_buf, test_buf, compressed_size) != 0) {
			is_ok = FALSE;
			std::cout << "[ERROR] Encrypted vs decrypted: not equal!" << std::endl;
		}
	}

	peconv::free_unaligned(test_buf);
	return is_ok;
}

BYTE* load_and_protect(BYTE *raw_pe, size_t raw_size, const char *key, size_t key_size, size_t &processed_len)
{
	BYTE *compressed_buf = peconv::alloc_aligned(raw_size, PAGE_READWRITE);
	if (!compressed_buf) {
		return nullptr;
	}
	std::cout << "Raw Size:" << raw_size << std::endl;
	ULONG compressed_size = 0;
	if (!protect::compress_buffer((const char*)raw_pe, raw_size, compressed_buf, raw_size, &compressed_size)) {
		std::cout << "Compression failed!" << std::endl;
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}

	std::cout << "[+] Compressed! Space savings: " << 1 - ((float)compressed_size / (float)raw_size) << std::endl;
	size_t enc_size = compressed_size + protect::CHUNK_SIZE;
	BYTE *enc_buf = peconv::alloc_aligned(enc_size, PAGE_READWRITE);
	if (!enc_buf) {
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}
	if (!test_compressed(raw_pe, raw_size, compressed_buf, compressed_size)) {
		std::cerr << "[ERROR] Compresion failed verification!" << std::endl;
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}
	if (protect::aes_crypt(compressed_buf, compressed_size, enc_buf, enc_size, &processed_len, key, key_size, false)) {
		std::cout << "AES success!" << std::endl;
		if (!test_encrypted(compressed_buf, compressed_size, enc_buf, enc_size, key, key_size)) {
			std::cerr << "[EROOR] Encryption failed verification!" << std::endl;
			peconv::free_aligned(enc_buf);
			enc_buf = nullptr;
		}
		peconv::free_aligned(compressed_buf);
		return enc_buf;
	}
	peconv::free_aligned(compressed_buf);
	peconv::free_aligned(enc_buf);
	return nullptr;
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		printf("<input_file> <output_file> <key>\n");
		system("pause");
		return 0;
	}
	size_t raw_size = 0;
	char* input_file = argv[1];
	char* output_file = argv[2];
	BYTE* raw_buf = peconv::load_file(input_file, raw_size);
	const char *key = argv[3];

	size_t processed_len = 0;
	BYTE* enc_buf = load_and_protect(raw_buf, raw_size, key, strlen(key), processed_len);
	if (!enc_buf) {
		peconv::free_resource_data(raw_buf);
		return -1;
	}

	if (peconv::dump_to_file(output_file, enc_buf, processed_len)) {
		std::cout << "Dumped file!" << std::endl;
	}
	peconv::free_resource_data(raw_buf);
	peconv::free_resource_data(enc_buf);
	return 0;
}

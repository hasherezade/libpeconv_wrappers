#include "protect.h"

#include "peconv.h"

BYTE* load_and_protect(BYTE *raw_pe, size_t raw_size, const char *key, size_t key_size, size_t &processed_len)
{
	BYTE *compressed_buf = peconv::alloc_aligned(raw_size, PAGE_READWRITE);
	if (!compressed_buf) {
		return nullptr;
	}
	std::cout << "Raw Size:" << raw_size << std::endl;
	ULONG compressed_size = 0;
	if (!protect::compress_buffer((const char*) raw_pe, raw_size, compressed_buf, raw_size, &compressed_size)) {
		std::cout << "Compression failed!" << std::endl;
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}

	std::cout << "Compression OK! Size:" << compressed_size << std::endl;
	size_t enc_size = compressed_size + protect::CHUNK_SIZE;
	BYTE *enc_buf = peconv::alloc_aligned(enc_size, PAGE_READWRITE);
	if (!enc_buf) {
		peconv::free_aligned(compressed_buf);
		return nullptr;
	}

	std::cout << "Compression success!" << std::endl;
	if (protect::aes_crypt(compressed_buf, compressed_size, enc_buf, enc_size, &processed_len, key, key_size, false)) {
		std::cout << "AES success!" << std::endl;
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
		system("pause");
		return -1;
	}

	if (peconv::dump_to_file(output_file, enc_buf, processed_len)) {
		std::cout << "Dumped file!" << std::endl;
	}
	peconv::free_resource_data(raw_buf);
	peconv::free_resource_data(enc_buf);
	system("pause");
	return 0;
}

#include "rtlcompress.h"

#include <iostream>

typedef NTSTATUS(__stdcall * _RtlDecompressBuffer)(
   USHORT CompressionFormat,
   PUCHAR UncompressedBuffer,
   ULONG UncompressedBufferSize,
   PUCHAR CompressedBuffer,
   ULONG CompressedBufferSize,
   PULONG FinalUncompressedSize
);

typedef NTSTATUS(__stdcall *_RtlCompressBuffer)(
  _In_  USHORT CompressionFormatAndEngine,
  _In_  PUCHAR UncompressedBuffer,
  _In_  ULONG  UncompressedBufferSize,
  _Out_ PUCHAR CompressedBuffer,
  _In_  ULONG  CompressedBufferSize,
  _In_  ULONG  UncompressedChunkSize,
  _Out_ PULONG FinalCompressedSize,
  _In_  PVOID  WorkSpace
);

typedef NTSTATUS(__stdcall *_RtlGetCompressionWorkSpaceSize)(
   USHORT CompressionFormatAndEngine,
   PULONG CompressBufferWorkSpaceSize,
   PULONG CompressFragmentWorkSpaceSize
);

BOOL protect::compress_buffer(const char *buffer, const ULONG bufferLen, UCHAR *compBuffer, ULONG compBufferLen, ULONG *compBufferSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (hNtdll == NULL) {
        return FALSE;
    }
    _RtlCompressBuffer RtlCompressBuffer = 
        (_RtlCompressBuffer) GetProcAddress(hNtdll, "RtlCompressBuffer");

   _RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize = 
       (_RtlGetCompressionWorkSpaceSize) GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");

    if (RtlCompressBuffer == NULL || RtlGetCompressionWorkSpaceSize == NULL) return FALSE;

   ULONG bufWorkspaceSize;  // Workspace Size
   ULONG fragWorkspaceSize; // Fragmented Workspace Size (Unused)
   NTSTATUS ret = RtlGetCompressionWorkSpaceSize(
                     COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormatAndEngine
                     &bufWorkspaceSize,                                     // CompressBufferWorkSpaceSize
                     &fragWorkspaceSize                                     // CompressFragmentWorkSpaceSize
                  );

   if (ret != S_OK) {
      return FALSE;
   }
#ifdef _DEBUG
   std::cout << "Compression Workspace Size: 0x" << std::hex << bufWorkspaceSize
             << std::dec << " (" << bufWorkspaceSize << ")" << std::endl;
#endif
   VOID *workspace = (VOID *)LocalAlloc(LMEM_FIXED, bufWorkspaceSize);
   if (workspace == NULL) {
      std::cout << "Failed to allocate space for workspace" << std::endl;
      return FALSE;
   }

   NTSTATUS result = RtlCompressBuffer(
                        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormatAndEngine
                        (UCHAR *)buffer,                                       // UncompressedBuffer
                        bufferLen,                                             // UncompressedBufferSize
                        compBuffer,                                            // CompressedBuffer
                        compBufferLen,                                         // CompressedBufferSize
                        4096,                                                  // UncompressedChunkSize
                        compBufferSize,                                        // FinalCompressedSize
                        workspace                                              // WorkSpace
                     );

   LocalFree(workspace);
   if (result != S_OK) {
      return FALSE;
   }
#ifdef _DEBUG
   std::cout << "Compressed Length: " << compBufferSize << std::endl;
#endif
   return TRUE;
}

BOOL protect::decompress_buffer(const char *buffer, const int bufferLen, UCHAR *uncompBuffer, const int uncompBufferLen, ULONG *uncompBufferSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    if (hNtdll == NULL) return FALSE;

   _RtlDecompressBuffer RtlDecompressBuffer = (_RtlDecompressBuffer) GetProcAddress(hNtdll, "RtlDecompressBuffer");
   if (RtlDecompressBuffer == NULL) {
       return FALSE;
   }
   NTSTATUS result = RtlDecompressBuffer(
                        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, // CompressionFormat
                        uncompBuffer,                                          // UncompressedBuffer
                        uncompBufferLen,                                       // UncompressedBufferSize
                        (UCHAR *)buffer,                                       // CompressedBuffer
                        bufferLen,                                             // CompressedBufferSize
                        uncompBufferSize                                       // FinalUncompressedSize
                     );

   if (result != S_OK) {
#ifdef _DEBUG
        printf("Error: %x\n", result);
#endif
        return FALSE;
   }

#ifdef _DEBUG
   std::cout << "Uncompressed Length: " << uncompBufferSize << std::endl;
#endif
   return TRUE;
}

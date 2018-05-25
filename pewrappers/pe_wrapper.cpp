#include "pe_wrapper.h"

bool PeWrapper::loadRes(peconv::hooking_func_resolver *my_resolver)
{
	size_t raw_size = 0;
	BYTE *raw_pe = peconv::load_resource_data(raw_size, this->resId, RT_RCDATA, peconv::get_current_module_handle());
	if (!raw_pe) {
#ifdef _DEBUG
		std::cerr << "Failed to load the resource!" << std::endl;
#endif
		return false;
	}
	bool is_ok = this->load(raw_pe, raw_size, my_resolver);
	peconv::free_resource_data(raw_pe);
	return is_ok;
}

bool PeWrapper::load(BYTE *raw_buffer, size_t raw_size, peconv::hooking_func_resolver *my_res)
{
	this->malware = peconv::load_pe_executable(raw_buffer, 
		raw_size, 
		this->vMalwareSize,
		(peconv::t_function_resolver*) my_res
		);

	if (!malware) {
		return false;
	}
	return true;
}

FARPROC PeWrapper::getFunction(DWORD rva)
{
	if (!malware || rva >= vMalwareSize) {
		return nullptr;
	}
	ULONGLONG func_offset = (ULONGLONG)malware + rva;
	return FARPROC(func_offset);
}

LPVOID PeWrapper::getBuffer(DWORD rva)
{
	if (!malware || rva >= vMalwareSize) {
		return nullptr;
	}
	ULONGLONG buf_offset = (ULONGLONG)malware + rva;
	return LPVOID(buf_offset);
}

bool PeWrapper::replaceTarget(DWORD rva_from, ULONGLONG va_to)
{
	BYTE *ptr = (BYTE*) getBuffer(rva_from);
	if (!peconv::replace_target(ptr, va_to)) {
		return false;
	}
	return true;
}

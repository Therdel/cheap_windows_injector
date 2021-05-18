// std api includes
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>                  // file input
#include <experimental/filesystem>  // exists, current_path, ::path::preferred_seperator
#include <chrono>                   // system_clock
#include <thread>                   // this_thread::sleep

// windows api includes
#include <windows.h>

// own includes
#include "ProcMemAccess.hpp"
#include "RAIIHandle.hpp"
#define DEFAULT_LOG_CHANNEL Log::Channel::STD_OUT
#include "Log.hpp"


using namespace std;

// Returns the last Win32 error, in string format. Returns an empty string if there is no error.
// adapted from: https://stackoverflow.com/a/17387176
std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if(errorMessageID == 0)
		return "No Error"; //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	                             NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

std::optional<DWORD> execute_function_remote(const ProcMemAccess &targetProc,
                              LPCSTR kern32_function,
                              LPCVOID param_buf,
                              SIZE_T param_size,
                              DWORD inject_timout) {
	std::optional<DWORD> l_result_remote_function;
	auto &l_hTargetProc = targetProc.getProcessHandle();

	//allocate space in target process for parameter
	LPVOID l_targetProcAllocAddress = VirtualAllocEx(l_hTargetProc.getRaw(),
	                                                 nullptr,
	                                                 param_size,
	                                                 MEM_RESERVE | MEM_COMMIT,
	                                                 PAGE_READWRITE);
	if (l_targetProcAllocAddress == NULL) {
		Log::log("Failed to allocate space in target process for ", kern32_function,
				" function parameter. Error: ", GetLastErrorAsString());
		return {};
	}

	// write parameter
	if (!targetProc.writeMemory(l_targetProcAllocAddress, param_buf, param_size)) {
		// writing to target process failed
		Log::log("Failed to write function parameter to target process");

		// deallocate parameter space
		if (VirtualFreeEx(l_hTargetProc.getRaw(), l_targetProcAllocAddress, 0, MEM_RELEASE) == 0) {
			Log::log("Failed to deallocate function parameter space in target process. Error: ", GetLastErrorAsString());
		}
		return {};
	}

	// base address of kernel32.dll in target process == base addr in every process
	HMODULE hKernel32 = ::GetModuleHandle("Kernel32");
	auto l_startRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, kern32_function);
	auto hThread = RAIIHandle(CreateRemoteThread(
			l_hTargetProc.getRaw(),   // handle
			// TODO? Add THREAD_QUERY_INFORMATION to security attributes
			NULL,                     // default security attributes
			0,             // default stack size
			l_startRoutine,           // function address in target process
			l_targetProcAllocAddress, // address of buffer holding function parameter in target process
			0,
			nullptr));
	if (!hThread.isValid()) {
		Log::log("Failed to create remote thread. Error: ", GetLastErrorAsString());
		return {};
	}

	// wait for thread to finish
	DWORD l_wait_ret = WaitForSingleObject(hThread.getRaw(), inject_timout);
	if (l_wait_ret == WAIT_TIMEOUT) {
		Log::log("Execution of remote thread took longer than ", inject_timout, "ms");
	} else if(l_wait_ret == WAIT_OBJECT_0){
		// get return value of function executed in remote
		DWORD l_result;
		if(GetExitCodeThread(hThread.getRaw(), &l_result) == 0) {
			Log::log("Failed to retrieve return code of LoadLibrary in remote process. Error: ",
					GetLastErrorAsString());
		} else {
			l_result_remote_function = l_result;
		}
	} else {
		Log::log("Execution of remote thread failed ");
	}

	// deallocate parameter space
	if (VirtualFreeEx(l_hTargetProc.getRaw(), l_targetProcAllocAddress, 0, MEM_RELEASE) == 0) {
		//freeing failed, whatever.
		Log::log("Failed to deallocate parameter space in target process. Error: ",
				GetLastErrorAsString());
	}

	return l_result_remote_function;
}

bool inject_dll(std::experimental::filesystem::path dll_path, const std::string &target_process_name, DWORD inject_timout) {
	bool l_success = true;
	//test if dll exists
	if(!experimental::filesystem::exists(dll_path)) {
		Log::log("Failed to find dll file");
		return false;
	}

	// ensure absolute path
	if(!dll_path.is_absolute()) {
		dll_path = experimental::filesystem::absolute(dll_path);
	}
	std::string l_dll_path_string = dll_path.string();

	// calculate end timepoint at which to stop trying to inject
	auto time_now = []() { return std::chrono::system_clock::now(); };
	std::chrono::system_clock::time_point l_inject_deadline;
	if (inject_timout == INFINITE) {
#undef max
		l_inject_deadline = std::chrono::system_clock::time_point::max();
	}
	else {
		l_inject_deadline = time_now() + std::chrono::system_clock::duration(std::chrono::milliseconds(inject_timout));
	}

	//open process
	DWORD l_accessRights =
			PROCESS_CREATE_THREAD |     //CreateRemoteThread
			PROCESS_QUERY_INFORMATION | //CheckRemoteDebuggerPresent
			PROCESS_VM_READ |           //ReadProcessMemory
			PROCESS_VM_WRITE |          //WriteProcessMemory
			PROCESS_VM_OPERATION;       //VirtualAllocEx, VirtualFreeEx

	std::optional<ProcMemAccess> l_targetProc;
	while (time_now() < l_inject_deadline) {
		l_targetProc = ProcMemAccess::wrap(target_process_name, l_accessRights);
		// sleep for some time if wrapping failed
		if (!l_targetProc.has_value()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		} else {
			break;
		}
	}

	if (!l_targetProc.has_value()) {
		Log::log("Failed to open process \"", target_process_name, "\"");
		return false;
	}

	Log::log("Injecting...");
	const RAIIHandle &l_hTargetProc = l_targetProc->getProcessHandle();

	size_t l_dllFilePathBytes = (l_dll_path_string.size() + 1) * sizeof(std::string::value_type);
	std::optional<DWORD> l_return_value = execute_function_remote(*l_targetProc,
	                                             "LoadLibraryA",
	                                             l_dll_path_string.data(),
	                                             l_dllFilePathBytes,
	                                             inject_timout);
	if(!l_return_value.has_value()) {
		l_success = false;
	} else {
		if(*l_return_value == 0) {
			Log::log("Remote LoadLibrary failed");
			l_success = false;
		} else {
			l_success = true;
		}
	}
	int exitCode = 42;
	execute_function_remote(*l_targetProc,
	                        "ExitProcess",
	                        &exitCode,
	                        sizeof(exitCode),
	                        inject_timout);
	/*
	//allocate space in target process for dll name
	//size is 1 greater than the .size() argument, because of null terminating character
	size_t l_dllFilePathBytes = (l_dll_path_wstring.size() + 1) * sizeof(std::wstring::value_type);
	LPVOID l_targetProcAllocAddress = VirtualAllocEx(l_hTargetProc.getRaw(),
	                                                 nullptr,
	                                                 l_dllFilePathBytes,
	                                                 MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (l_targetProcAllocAddress == nullptr) {
		Log::log("Failed to allocate space in target process");
		return false;
	}

	//write file path
	if (!l_targetProc->writeMemory(l_targetProcAllocAddress, l_dll_path_wstring.c_str(), l_dllFilePathBytes)) {
		//writing to target process failed
		Log::log("Failed to write dll path to target process");

		//deallocate file name space
		if (VirtualFreeEx(l_hTargetProc.getRaw(), l_targetProcAllocAddress, 0, MEM_RELEASE) == 0) {
			Log::log("Failed to deallocate space in target process");
		}
		return false;
	}

	//TODO: dynamically read base address of kernel32.dll in target process
	//this only works, because in practice, kernel32.dll is loaded into the same virtual address of every process
	HMODULE hKernel32 = ::GetModuleHandle("Kernel32");
	// load dll into target process
	// (via CreateRemoteThread & LoadLibrary)
	// TODO: Test correct injection with module iteration
	auto l_startRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	RAIIHandle hThread = CreateRemoteThread(
			l_hTargetProc.getRaw(),   // handle
			NULL,                     // default security attributes
			0,                        // default stack size
			l_startRoutine,           // loadlibraryw address in foreign process
			l_targetProcAllocAddress, // address of buffer holding loadlibw parameter in foreign process
			0,
			nullptr);
	if (!hThread.isValid()) {
		Log::log("Failed to create remote thread");
		return false;
	}

	//wait for thread to finish
	DWORD l_wait_ret = WaitForSingleObject(hThread.getRaw(), inject_timout);
	if (l_wait_ret == WAIT_TIMEOUT) {
		Log::log("Execution of DLLMain took longer than ", inject_timout, "ms");
		return false;
	}

	// TODO: Test inject LoadLibraryW HMODULE return value
	// get return value of function executed in remote
	DWORD l_ret_load_library;
	if(GetExitCodeThread(hThread.getRaw(), &l_ret_load_library) == 0) {
		Log::log("Failed to retrieve return code of LoadLibrary in remote process. Error: ",
				GetLastErrorAsString());
		l_success = false;
	} else {
		if(l_ret_load_library == 0) {
			Log::log("Remote LoadLibrary failed");
			l_success = false;
		}
	}

	//deallocate file name space
	if (VirtualFreeEx(l_hTargetProc.getRaw(), l_targetProcAllocAddress, 0, MEM_RELEASE) == 0) {
		//freeing failed, whatever.
		Log::log("Failed to deallocate space in target process");
		return false;
	}

	 */

	return l_success;
}

/*
// from https://stackoverflow.com/questions/10737644/convert-const-char-to-wstring
std::wstring string_to_wstring(const std::string& str)
{
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

// necessary because this conversion method is deprecated in c++17
// TODO remove use of deprecated code
//#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
// converts all arguments in argv to wstrings
// copied from http://www.cplusplus.com/forum/general/153269/
std::vector<std::wstring> get_wchar_args(int argc, char **argv) {
	// http://en.cppreference.com/w/cpp/locale/wstring_convert
	//std::wstring_convert< std::codecvt<wchar_t, char, std::mbstate_t> > l_converter;
	// use std::wstring_convert< codecvt_utf8<wchar_t> > if UTF-8 to wchar_t conversion is required

	std::vector<std::wstring> l_wchar_args;
	for (int i = 0; i < argc; ++i) {
		//l_wchar_args.push_back(l_converter.from_bytes(argv[i]));
		l_wchar_args.push_back(string_to_wstring(argv[i]));
	}

	return l_wchar_args;
}
*/

int main(int argc, char **argv)
{
	std::cout
#if _WIN64
			<< "WIN64"
			#else
			<< "WIN32"
			#endif
			<< std::endl;
	DWORD l_inject_timeout = INFINITE;

	// ensure at least 2 arguments - dllpath and target proc name
	if (argc < 3) {
		Log::log("Arguments: DLLPath TargetProcessName [timeout in ms]");
		return 0;
	}

	//auto l_wchar_args = get_wchar_args(argc, argv);

	// read file path from cmdline args
	experimental::filesystem::path l_dllFilePath = argv[1];
	string l_targetProcName = argv[2];

	Log::log("DLL:     ", l_dllFilePath);
	Log::log("Process: ", l_targetProcName);

	// if given, parse timeout value
	if (argc > 3) {
		l_inject_timeout = std::stol(argv[3]);
		Log::log("Timeout: ", l_inject_timeout);
	}

	Log::log("");
	Log::log("Waiting for Process...");

	bool l_success = inject_dll(l_dllFilePath, l_targetProcName, l_inject_timeout);

	Log::log("");

	if (l_success)
		Log::log("Injection successful");
	else
		Log::log("Injection failed");

	return 0;
}
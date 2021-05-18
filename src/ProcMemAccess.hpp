#pragma once

#include <string>
#include <map>
#include <windows.h>
#include <optional>

#include "RAIIHandle.hpp"

class ProcMemAccess {
private:
	std::string m_processName;
	DWORD m_processID;
	RAIIHandle m_processHandle;

	int m_nextModuleDescriptor;
	std::map<std::string, int> m_moduleDescriptors;
	std::map<int, DWORD> m_knownModuleBaseAddresses;

	ProcMemAccess(std::string processName, DWORD processID, HANDLE processHandle);

	int produceNewModuleDescriptor() { return m_nextModuleDescriptor++; };

	//returns the PID of a process with given processName, if present
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
	static std::optional<DWORD> getPIDByName(const std::string &processName);

	//retrieves the base address of the loaded module with given moduleName, if present
	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms686849(v=vs.85).aspx
	static std::optional<uintptr_t> getModuleBaseAddr32(const std::string &moduleName, DWORD dwPID);

	//gets the module base addr in opened process of given moduleName
	//bool getModuleBaseAddr(const std::string& moduleName, HANDLE processHandle, PVOID& baseAddrOut);

public:
	//provide access to a process with given name
	static std::optional<ProcMemAccess> wrap(const std::string &processName, DWORD accessRights);

	//returns the handle of the wrapped process. INVALID_HANDLE_VALUE if none is wrapped.
	const RAIIHandle &getProcessHandle() const;

	std::optional<int> getModuleDescriptor(const std::string &moduleName);

	// c-style read/write process memory

	/*
	Reads from the relative address space of a processes loaded module
	moduleDescriptor: moduleDescriptor returned
	addr: base address to read from of target process
	buf: buffer to read into
	bytesToRead: # bytes to read from process memory into buf
	numberOfBytesRead: # bytes actually read
	*/
	bool readMemory(LPCVOID addr, LPVOID buf, SIZE_T bytesToRead) const;

	/*
	Reads from the process address space
	addr: base address to read from of target process
	buf: buffer to read into
	bytesToRead: # bytes to read from process memory into buf
	numberOfBytesRead: # bytes actually read
	*/
	bool readMemory(int moduleDescriptor, LPCVOID moduleRelativeAddr, LPVOID buf, SIZE_T bytesToRead) const;

	/*
	Writes to the process address space
	addr: base address to write to of target process
	buf: buffer to read from
	bytesToWrie: # bytes to write to process memory from buf
	numberOfBytesWritten: # bytes actually written
	*/
	bool writeMemory(LPVOID addr, LPCVOID buf, SIZE_T bytesToWrite) const;

	bool writeMemory(int moduleDescriptor, LPVOID moduleRelativeAddr, LPCVOID buf, SIZE_T bytesToWrite) const;

	// c++-style read/write process memory

	template<typename T>
	std::optional<T> readMemory(LPCVOID addr) const {
		std::optional<T> l_return;
		if (ReadProcessMemory(m_processHandle.getRaw(), addr, &(*l_return), sizeof(T), NULL) == 0) {
			return std::nullopt;
		}

		return l_return;
	}

	template<typename T>
	std::optional<T> readMemory(int moduleDescriptor, LPCVOID moduleRelativeAddr) {
		auto l_it = m_knownModuleBaseAddresses.find(moduleDescriptor);
		if (l_it != m_knownModuleBaseAddresses.end()) {
			std::optional<T> l_return;
			DWORD l_moduleBaseAddr = m_knownModuleBaseAddresses.at(moduleDescriptor);
			//interpret LPCVOID as DWORD, assuming 32 bit address
			LPCVOID l_newAddress = reinterpret_cast<LPCVOID>((reinterpret_cast<DWORD>(moduleRelativeAddr)) +
			                                                 l_moduleBaseAddr);
			return readMemory(l_newAddress, &(*l_return), sizeof(T), NULL);
		} else {
			return {};
		}
	}

	template<typename T>
	bool writeMemory(LPVOID addr, const T &value) const {
		return WriteProcessMemory(m_processHandle.getRaw(), addr, &value, sizeof(T), NULL);
	}

	template<typename T>
	bool writeMemory(int moduleDescriptor, LPVOID moduleRelativeAddr, const T &value) const {
		auto l_it = m_knownModuleBaseAddresses.find(moduleDescriptor);
		if (l_it != m_knownModuleBaseAddresses.end()) {
			DWORD l_moduleBaseAddr = m_knownModuleBaseAddresses.at(moduleDescriptor);
			//interpret LPVOID as DWORD, assuming 32 bit address
			LPVOID l_newAddress = reinterpret_cast<LPVOID>((reinterpret_cast<DWORD>(moduleRelativeAddr)) +
			                                               l_moduleBaseAddr);
			return writeMemory(l_newAddress, &value, sizeof(T), NULL);
		} else {
			return false;
		}
	}
};
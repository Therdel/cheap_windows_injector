#include <iostream>

#include <windows.h>
#include <TlHelp32.h>     //PROCESSENTRY32, CreateToolhelp32Snapshot, Process32First, Process32Next

#include "ProcMemAccess.hpp"
#include "Log.hpp"

ProcMemAccess::ProcMemAccess(std::string processName, DWORD processID, HANDLE processHandle)
  : m_processName(std::move(processName))
  , m_processID(processID)
  , m_processHandle(processHandle)
  , m_nextModuleDescriptor(0)
  , m_moduleDescriptors()
  , m_knownModuleBaseAddresses() {
}

std::optional<DWORD> ProcMemAccess::getPIDByName(const std::string &processName) {
  PROCESSENTRY32 pe32;

  // Take a snapshot of all processes in the system.
  auto hProcessSnap = RAIIHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (hProcessSnap.isValid() == false) {
    return {};
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if (!Process32First(hProcessSnap.getRaw(), &pe32)) {
    return {};
  }

  bool foundMatch = false;

  // Now walk the snapshot of processes
  std::optional<DWORD> l_pid;
  do {
    if (processName.compare(pe32.szExeFile) == 0) {
      //process with queried name found
      l_pid = pe32.th32ProcessID;
      foundMatch = true;
      break;
    }
  } while (Process32Next(hProcessSnap.getRaw(), &pe32));
  return l_pid;
}

std::optional<uintptr_t> ProcMemAccess::getModuleBaseAddr32(const std::string& moduleName, DWORD dwPID) {
  // Take a snapshot of all modules in the specified process. (32 & 64 bit)
  auto hModuleSnap = RAIIHandle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID));
  if (hModuleSnap.isValid() == false) {
    return {};
  }

  MODULEENTRY32 me32;
  // Set the size of the structure before using it.
  me32.dwSize = sizeof(MODULEENTRY32);

  // Retrieve information about the first module,
  // and exit if unsuccessful
  if (!Module32First(hModuleSnap.getRaw(), &me32)) {
    return {};
  }

  std::optional<uintptr_t> l_modBaseAddr;
  // Now walk the module list of the process
  do {
    //compare module names
    if (moduleName == me32.szModule) {
      //module name is as queried
      l_modBaseAddr = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
      break;
    }
  } while (Module32Next(hModuleSnap.getRaw(), &me32));

  return l_modBaseAddr;
}

std::optional<ProcMemAccess> ProcMemAccess::wrap(const std::string &processName, DWORD accessRights) {
  //retrieve process id
  std::optional<DWORD> l_processID = getPIDByName(processName);
  if(!l_processID.has_value()) {
    return std::nullopt;
  }

  //get handle to process
  HANDLE l_processHandle = OpenProcess(
    accessRights,
    FALSE,
    *l_processID);
  if (l_processHandle == NULL) {
    return std::nullopt;
  }

  //everything worked, store process data
  return ProcMemAccess(processName, l_processID.value(), l_processHandle);
}

const RAIIHandle &ProcMemAccess::getProcessHandle() const {
  return m_processHandle;
}

std::optional<int> ProcMemAccess::getModuleDescriptor(const std::string &moduleName) {
  std::optional<int> l_descriptor;
  //check if module name is already known
  auto l_it = m_moduleDescriptors.find(moduleName);
  if (l_it != m_moduleDescriptors.end()) {
    //found existing descriptor
    l_descriptor = l_it->second;
  }
  else {
    //moduleName unknown
    std::optional<DWORD> l_moduleBaseAddress = getModuleBaseAddr32(moduleName, m_processID);
    // ensure the module was found in the process
    if(l_moduleBaseAddress.has_value()) {
      //save descriptor and base address
      int l_newModuleDescriptor = produceNewModuleDescriptor();
      m_moduleDescriptors[moduleName] = l_newModuleDescriptor;
      m_knownModuleBaseAddresses[l_newModuleDescriptor] = *l_moduleBaseAddress;

      //return descriptor
      l_descriptor = { l_newModuleDescriptor };
    }
  }

  return l_descriptor;
}

bool ProcMemAccess::readMemory(LPCVOID addr, LPVOID buf, SIZE_T bytesToRead) const {
  return ReadProcessMemory(m_processHandle.getRaw(), addr, buf, bytesToRead, NULL);
}

bool ProcMemAccess::readMemory(int moduleDescriptor, LPCVOID moduleRelativeAddr, LPVOID buf, SIZE_T bytesToRead) const {
  auto l_it = m_knownModuleBaseAddresses.find(moduleDescriptor);
  if (l_it != m_knownModuleBaseAddresses.end()) {
    DWORD l_moduleBaseAddr = m_knownModuleBaseAddresses.at(moduleDescriptor);
    //interpret LPCVOID as DWORD, assuming 32 bit address
    LPCVOID l_newAddress = reinterpret_cast<LPCVOID>((reinterpret_cast<uintptr_t>(moduleRelativeAddr)) + l_moduleBaseAddr);
    return readMemory(l_newAddress, buf, bytesToRead);
  }
  else {
    return false;
  }
}

bool ProcMemAccess::writeMemory(LPVOID addr, LPCVOID buf, SIZE_T bytesToWrite) const {
  return WriteProcessMemory(m_processHandle.getRaw(), addr, buf, bytesToWrite, NULL);
}

bool ProcMemAccess::writeMemory(int moduleDescriptor, LPVOID moduleRelativeAddr, LPCVOID buf, SIZE_T bytesToWrite) const {
  auto l_it = m_knownModuleBaseAddresses.find(moduleDescriptor);
  if (l_it != m_knownModuleBaseAddresses.end()) {
    DWORD l_moduleBaseAddr = m_knownModuleBaseAddresses.at(moduleDescriptor);
    //interpret LPVOID as DWORD, assuming 32 bit address
    LPVOID l_newAddress = reinterpret_cast<LPVOID>((reinterpret_cast<uintptr_t>(moduleRelativeAddr)) + l_moduleBaseAddr);
    return writeMemory(l_newAddress, buf, bytesToWrite);
  }
  else {
    return false;
  }
}
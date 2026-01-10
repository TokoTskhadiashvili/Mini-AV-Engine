#pragma once

#include <functional>
#include <filesystem>
#include <map>

#include <Windows.h>
#include <Wininet.h>
#include <TlHelp32.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

std::string _JsonEscape(const std::string& s) {
	std::string output;
	output.reserve(s.size());
	for (char character : s) {
		switch (character) {
		case '"':  output += "\\\""; break;
		case '\\': output += "\\\\"; break;
		case '\b': output += "\\b";  break;
		case '\f': output += "\\f";  break;
		case '\n': output += "\\n";  break;
		case '\r': output += "\\r";  break;
		case '\t': output += "\\t";  break;
		default:   output += character;
		}
	}

	return output;
}

std::string _GetPathWithPID(DWORD pid) {
	HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	if (!process) {
		return "";
	}

	char path[MAX_PATH];
	DWORD size = MAX_PATH;

	if (!QueryFullProcessImageNameA(process, 0, path, &size)) {
		CloseHandle(process);
		return "";
	}

	CloseHandle(process);
	return std::string(path);
}

DWORD _GetIntegrityLevel(HANDLE& token) {
	DWORD size = 0;

	GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
	TOKEN_MANDATORY_LABEL* token_label = (TOKEN_MANDATORY_LABEL*)malloc(size);
	memset(token_label, 0, size);

	GetTokenInformation(token, TokenIntegrityLevel, token_label, size, &size);

	DWORD integrity_level = *GetSidSubAuthority(token_label->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(token_label->Label.Sid)) - 1);

	free(token_label);
	return integrity_level;
}

bool _MemorySearch(unsigned char* buffer, size_t buffer_size, unsigned char* target, size_t target_size) {
	if (buffer == NULL|| target == NULL || target_size == 0 || buffer_size == 0 || buffer_size < target_size) {
		return false;
	}

	for (size_t i = 0; i < buffer_size - target_size; ++i) {
		if (memcmp(buffer + 1, target, buffer_size) == 0) {
			return true;
		}
	}

	return false;
}

void UpdateProcessList(std::map<DWORD, bool>& process_list) {
	HANDLE self_token;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self_token)) {
		return;
	}

	DWORD self_token_label = _GetIntegrityLevel(self_token);
	CloseHandle(self_token);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return;
	}

	PROCESSENTRY32 proc_entry;
	proc_entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot, &proc_entry)) {
		CloseHandle(snapshot);
		return;
	}

	do {
		HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_entry.th32ProcessID);
		if (!process) {
			continue;
		}

		HANDLE token;
		if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
			CloseHandle(process);
			continue;
		}

		DWORD token_label = _GetIntegrityLevel(token);
		if (token_label < self_token_label) {
			process_list.insert({ proc_entry.th32ProcessID, false });
		}

		CloseHandle(token);
		CloseHandle(process);
	} while (Process32Next(snapshot, &proc_entry));

	CloseHandle(snapshot);
	return;
}

void ScanProcesses(HINTERNET& connection, std::vector<std::string>& local_indicators, std::map<DWORD, bool>& process_list, void (*AlertServer)(HINTERNET&, std::string&)) {
	for (const auto& [pid, malicious] : process_list) {
		HANDLE process = OpenProcess(0, FALSE, pid);
		if (process == INVALID_HANDLE_VALUE) {
			continue;
		}

		MEMORY_BASIC_INFORMATION memory_info{};
		
		size_t buffer_size = 32768;
		unsigned char* buffer = (unsigned char*)malloc(buffer_size);
		if (buffer == NULL) {
			continue;
		}
		memset(buffer, 0, buffer_size);
		uintptr_t address = 0;

		while (VirtualQueryEx(process, (LPCVOID)address, &memory_info, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(memory_info)) {
			if (memory_info.State != MEM_COMMIT) {
				continue;
			}

			if ((memory_info.Protect & PAGE_GUARD) || (memory_info.Protect && PAGE_NOACCESS) || !(memory_info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
				continue;
			}

			uintptr_t base = (uintptr_t)memory_info.BaseAddress;
			SIZE_T size = memory_info.RegionSize;
			SIZE_T offset = 0;
			while (offset < size) {
				SIZE_T to_read = min(sizeof(buffer_size), size - offset);
				SIZE_T read = 0;

				if (!ReadProcessMemory(process, (LPCVOID)(base + offset), buffer, to_read, &read)) {
					break;
				}

				for (const std::string& indicator : local_indicators) {
					if (indicator.length() > 4 && indicator.substr(indicator.length() - 4) != ".bin") {
						continue;
					}

					std::string path = "indicators/bin/";
					path += indicator;

					std::ifstream indicator_file(path, std::ios::binary);
					if (!indicator_file.is_open()) {
						continue;
					}

					std::uintmax_t indicator_size = std::filesystem::file_size(path);
					unsigned char* indicator_buffer = (unsigned char*)malloc(indicator_size);
					memset(indicator_buffer, 0, indicator_size);

					indicator_file.read((char*)indicator_buffer, indicator_size);
					indicator_file.close();

					bool final = _MemorySearch(buffer, buffer_size, indicator_buffer, indicator_size);
					free(indicator_buffer);
					if (!final) {
						continue;
					}

					std::string binary_path = _GetPathWithPID(pid);

					std::string message = "Malicious process detected";
					std::string data =
						"{"
							"\"message\": \"" + _JsonEscape(message) + "\", "
							"\"type\": \"process\", "
							"\"details\": {"
								"\"pid\": " + std::to_string(pid) + ", "
								"\"path\" : \"" + _JsonEscape(binary_path) + "\", "
								"\"indicator\": \"" + _JsonEscape(indicator) + "\""
							"}"
						"}";
					AlertServer(connection, data);
				}

				memset(buffer, 0, buffer_size);
				offset += to_read;
			}
		}

		CloseHandle(process);
		free(buffer);
	}
}

void KillAllMalicious(std::map<DWORD, bool> process_list) {
	for (const auto& [pid, malicious] : process_list) {
		HANDLE process = OpenProcess(0, false, pid);
		if (!process) {
			continue;
		}

		TerminateProcess(process, -1);
	}
}

void ScanFiles(HINTERNET& connection, std::vector<std::string>& local_indicators, std::vector<std::string>& target_directories, void (*AlertServer)(HINTERNET&, std::string&)) {
	std::vector<std::string> hashes;

	for (const auto& indicator : local_indicators) {
		if (indicator.length() > 4 && indicator.substr(indicator.length() - 4) != ".txt") {
			continue;
		}

		std::string path = "indicators/txt/";
		path += indicator;

		std::uintmax_t indicator_size = std::filesystem::file_size(path);

		char* indicator_data = (char*)malloc(indicator_size);
		if (indicator_data == NULL) {
			continue;
		}
		memset(indicator_data, 0, indicator_size);

		std::ifstream file(path, std::ios::out);
		file.read(indicator_data, indicator_size);

		std::string indicator_string = indicator_data;
		free(indicator_data);

		std::istringstream iss(indicator_string);
		std::string line;

		while (std::getline(iss, line)) {
			if (!line.empty()) {
				hashes.push_back(line);
			}
		}

		for (const auto& directory : target_directories) {
			WIN32_FIND_DATAA data;
			std::string path = directory + "\\*";

			HANDLE find = FindFirstFileA(path.c_str(), &data);
			if (find == INVALID_HANDLE_VALUE) {
				continue;
			}

			do {
				BCRYPT_ALG_HANDLE h_alg = nullptr;
				BCRYPT_HASH_HANDLE h_hash = nullptr;

				NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
				if (!BCRYPT_SUCCESS(status)) {
					continue;
				}

				DWORD hash_object_size = 0, cb_data, hash_size = 0;

				if (!BCRYPT_SUCCESS(BCryptGetProperty(h_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_size, sizeof(DWORD), &cb_data, 0)) ||
					!BCRYPT_SUCCESS(BCryptGetProperty(h_alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_size, sizeof(DWORD), &cb_data, 0))) {
					continue;
				}

				std::vector<BYTE> hash_object(hash_object_size);
				std::vector<BYTE> hash(hash_size);

				if (!BCRYPT_SUCCESS(BCryptCreateHash(h_alg, &h_hash, hash_object.data(), hash_object_size, nullptr, 0, 0))) {
					continue;
				}

				std::ifstream file(path, std::ios::binary);
				if (!file) {
					continue;
				}

				size_t buffer_size = 4096;
				BYTE* buffer = (BYTE*)malloc(buffer_size);
				if (buffer == NULL) {
					continue;
				}
				memset(buffer, 0, buffer_size);

				while (file.read((char*)buffer, sizeof(BYTE) * buffer_size) || file.gcount() > 0) {
					if (!BCRYPT_SUCCESS(BCryptHashData(h_hash, buffer, (ULONG)file.gcount(), 0))) {
						free(buffer);
						continue;
					}
				}
				free(buffer);

				if (!BCRYPT_SUCCESS(BCryptFinishHash(h_hash, hash.data(), hash_size, 0))) {
					continue;
				}

				std::string hash_string;
				hash_string.reserve(hash.size() * 2);
				for (BYTE byte : hash) {
					const char hex[] = "0123456789abcdef";
					hash_string.push_back(hex[(byte >> 4) & 0xF]);
					hash_string.push_back(hex[byte & 0xF]);
				}

				for (const auto& f_hash : hashes) {
					if (hash_string != f_hash)
						continue;

					std::string message = "Malicious file found";
					std::string s_data =
						"{"
							"\"message\": \"" + _JsonEscape(message) + "\", "
							"\"type\": \"file\", "
							"\"details\": {"
								"\"path\" : \"" + _JsonEscape(data.cFileName) + "\", "
								"\"indicator\": \"" + _JsonEscape(indicator) + "\""
							"}"
						"}";

					AlertServer(connection, s_data);
				}
			} while (FindNextFileA(find, &data) != 0);

			FindClose(find);
		}
	}
}
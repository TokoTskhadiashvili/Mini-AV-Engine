#pragma once

#include <functional>
#include <filesystem>

#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

class AVEngine {
private:
	std::vector<DWORD> process_list;
	std::vector<DWORD> malicious_process_list;
	std::vector<std::string> scan_directory_list;
	std::vector<std::string> malicious_file_list;

	DWORD get_integrity_level(HANDLE& token) {
		DWORD size = 0;

		GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
		TOKEN_MANDATORY_LABEL* token_label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(malloc(size));
		memset(token_label, 0, size);

		GetTokenInformation(token, TokenIntegrityLevel, token_label, size, &size);

		DWORD integrity_level = *GetSidSubAuthority(token_label->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(token_label->Label.Sid)) - 1);

		free(token_label);
		return integrity_level;
	}

	bool memory_search(unsigned char* parent_buffer, size_t parent_buffer_size, unsigned char* child_buffer, size_t child_buffer_size) {
		if (!parent_buffer || !child_buffer || child_buffer_size == 0 || parent_buffer_size == 0 || parent_buffer_size < child_buffer_size) {
			return false;
		}

		for (size_t i = 0; i < parent_buffer_size - child_buffer_size; ++i) {
			if (memcmp(parent_buffer + i, child_buffer, child_buffer_size) == 0) {
				return true;
			}
		}

		return false;
	}

public:
	void init_scan_directories(std::vector<std::string>& directories) {
		scan_directory_list = directories;
	}

	bool update_process_list() {
		HANDLE self_token;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self_token)) {
			return false;
		}

		DWORD self_token_label = get_integrity_level(self_token);
		CloseHandle(self_token);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		PROCESSENTRY32 proc_entry;
		proc_entry.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(snapshot, &proc_entry)) {
			CloseHandle(snapshot);
			return false;
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

			DWORD token_label = get_integrity_level(token);
			if (token_label < self_token_label) {
				process_list.push_back(proc_entry.th32ProcessID);
			}

			CloseHandle(token);
			CloseHandle(process);
		} while (Process32Next(snapshot, &proc_entry));

		CloseHandle(snapshot);
		return true;
	}

	void scan_processes(std::vector<std::string>& rules, const std::function<bool(std::string&)>& alert) {
		for (const auto& pid : process_list) {
			HANDLE process = OpenProcess(0, FALSE, pid);
			if (process == INVALID_HANDLE_VALUE) {
				continue;
			}

			MEMORY_BASIC_INFORMATION memory_info{};
			unsigned char* buffer = reinterpret_cast<unsigned char*>(malloc(32768));
			if (buffer == NULL) {
				continue;
			}
			memset(buffer, 0, 32768);
			uintptr_t address = 0;

			while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory_info, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(memory_info)) {
				if (memory_info.State == MEM_COMMIT) {
					if ((!(memory_info.Protect & PAGE_GUARD) && !(memory_info.Protect && PAGE_NOACCESS)) && memory_info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
						uintptr_t base = reinterpret_cast<uintptr_t>(memory_info.BaseAddress);
						SIZE_T size = memory_info.RegionSize;
						SIZE_T offset = 0;

						while (offset < size) {
							SIZE_T to_read = min(sizeof(32768), size - offset);
							SIZE_T read = 0;

							if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + offset), buffer, to_read, &read)) {
								for (const auto& rule : rules) {
									if (rule.length() > 4 && rule.substr(rule.length() - 4) != ".bin") {
										continue;
									}

									std::string rule_path = "";
									rule_path += "./rules/";
									rule_path += rule;

									std::ifstream rule_file(rule_path, std::ios::binary);
									if (!rule_file.is_open()) {
										continue;
									}

									std::uintmax_t rule_size = std::filesystem::file_size(rule_path);
									unsigned char* rule_buffer = reinterpret_cast<unsigned char*>(malloc(rule_size));
									memset(rule_buffer, 0, rule_size);

									rule_file.read(reinterpret_cast<char*>(rule_buffer), rule_size);
									rule_file.close();

									bool malicious = memory_search(buffer, 32768, rule_buffer, rule_size);
									free(rule_buffer);

									if (!malicious) {
										continue;
									}

									// Send Alert
									std::string message = "[WARNING]: Malicious process detected";
									std::string data = "{\"message\": \"" + message + "\", \"pid\": " + std::to_string(pid) + ", \"rule\": \"" + rule + "\"}";
									alert(data);
									malicious_process_list.push_back(pid);
								}
							}

							memset(buffer, 0, 32768);
							offset += to_read;
						}
					}
				}
			}

			CloseHandle(process);
			free(buffer);
		}
	}

	void kill_malicious() {
		for (const auto& pid : malicious_process_list) {
			HANDLE process = OpenProcess(0, FALSE, pid);
			if (!process) {
				continue;
			}
			
			TerminateProcess(process, 0);
			CloseHandle(process);
		}
	}

	void scan_disk(std::vector<std::string>& rules, const std::function<bool(std::string&)>& alert) {
		std::vector<std::string> hashes;

		for (const auto& rule : rules) {
			if (rule.length() > 4 && rule.substr(rule.length() - 4) != ".txt") {
				continue;
			}

			std::string rule_path = "";
			rule_path += "./rules/";
			rule_path += rule;
			std::uintmax_t rule_size = std::filesystem::file_size(rule_path);

			char* rule_data = reinterpret_cast<char*>(malloc(rule_size));
			if (rule_data == NULL) {
				continue;
			}
			memset(rule_data, 0, rule_size);
			std::ifstream rule_file(rule_path, std::ios::out);
			rule_file.read(rule_data, rule_size);

			std::string rule_str = rule_data;
			free(rule_data);

			std::istringstream iss(rule_str);
			std::string line;

			while (std::getline(iss, line)) {
				if (!line.empty()) {
					hashes.push_back(line);
				}
			}
		}

		for (const auto& directory : scan_directory_list) {
			WIN32_FIND_DATAA find_data;
			std::string path = directory + "\\*";

			HANDLE find = FindFirstFileA(path.c_str(), &find_data);
			if (find == INVALID_HANDLE_VALUE) {
				continue;
			}

			do {
				std::string filename = find_data.cFileName;

				if (filename == "." || filename == "..") {
					continue;
				}

				if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
					BCRYPT_ALG_HANDLE h_alg = nullptr;
					BCRYPT_HASH_HANDLE h_hash = nullptr;

					NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
					if (BCRYPT_SUCCESS(status)) {
						DWORD hash_object_size = 0, cb_data = 0, hash_length = 0;

						if (BCRYPT_SUCCESS(BCryptGetProperty(h_alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hash_object_size), sizeof(DWORD), &cb_data, 0)) &&
							BCRYPT_SUCCESS(BCryptGetProperty(h_alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(DWORD), &cb_data, 0))) {
							std::vector<BYTE> hash_object(hash_object_size);
							std::vector<BYTE> hash(hash_length);

							if (BCRYPT_SUCCESS(BCryptCreateHash(h_alg, &h_hash, hash_object.data(), hash_object_size, nullptr, 0, 0))) {
								std::ifstream file(path, std::ios::binary);
								if (file) {
									BYTE buffer[4096];
									memset(buffer, 0, sizeof(BYTE) * 4096);
									while (file.read(reinterpret_cast<char*>(buffer), sizeof(BYTE) * 4096) || file.gcount() > 0) {
										if (!BCRYPT_SUCCESS(BCryptHashData(h_hash, buffer, static_cast<ULONG>(file.gcount()), 0))) {
											break;
										}
									}

									if (BCRYPT_SUCCESS(BCryptFinishHash(h_hash, hash.data(), hash_length, 0))) {
										std::string hash_string;

										hash_string.reserve(hash.size() * 2);
										for (BYTE byte : hash) {
											const char hex[] = "0123456789abcdef";
											hash_string.push_back(hex[(byte >> 4) & 0xF]);
											hash_string.push_back(hex[byte & 0xF]);
										}

										for (const auto& l_hash : hashes) {
											if (l_hash == hash_string) {
												// Send Alert
												std::string message = "[WARNING]: Malicious file detected";
												std::string data = "{\"message\": \"" + message + "\", \"filename\": " + path + ", \"rule\": \"" + rule + "\"}";
												alert(data);
												malicious_file_list.push_back(path);
											}
										}
									}
								}
							}
						}
					}
				}
			} while (FindNextFileA(find, &find_data) != 0);

			FindClose(find);
		}
	}

	void delete_malicious() {
		for (const auto& file : malicious_file_list) {
			DeleteFileA(file.c_str());
		}
	}
};

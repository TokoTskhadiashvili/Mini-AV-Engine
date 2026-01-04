#pragma once

#include "config.hpp"

#include <filesystem>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <thread>

#include <Windows.h>
#include <Wininet.h>
#include <tlhelp32.h>

#pragma comment(lib, "wininet.lib")

class HttpClient {
private:
	HINTERNET session = nullptr;
	HINTERNET connection = nullptr;
	std::vector<std::string> repo_rules;
	std::vector<std::string> local_rules;

public:
	bool connect(const char* host, const char* user_agent) {
		session = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
		if (!session) {
			return false;
		}

		connection = InternetConnectA(session, host, 0, "", "", INTERNET_SERVICE_HTTP, 0, 0);
		if (!connection) {
			return false;
		}

		return true;
	}

	std::vector<std::string> get_local_rules() {
		return local_rules;
	}

	bool populate_file_list(const char* host) {
		std::string data;
		HINTERNET file = InternetOpenUrlA(session, host, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
		if (!file) {
			return false;
		}

		char tmp_buffer[4096];
		memset(tmp_buffer, 0, 4096);
		DWORD bytes_read = 0;

		while (InternetReadFile(file, tmp_buffer, sizeof(tmp_buffer), &bytes_read) && bytes_read != 0) {
			data.append(tmp_buffer, bytes_read);
		}

		InternetCloseHandle(file);

		if (data.size() >= 3 && (unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF) {
			data.erase(0, 3);
		}

		std::istringstream iss(data);
		std::string line;

		while (std::getline(iss, line)) {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}

			if (!line.empty()) {
				repo_rules.push_back(line);
			}
		}

		return true;
	}

	bool update_rules(std::vector<std::string> &local_rules) {
		repo_rules.erase(
			std::remove_if(
				repo_rules.begin(),
				repo_rules.end(),
				[&](const std::string& rule) {
					return std::find(local_rules.begin(), local_rules.end(), rule) != local_rules.end();
				}
			),
			repo_rules.end()
		);

		return true;
	}

	bool download_rules() {
		for (const auto& repo_rule : repo_rules) {
			std::string url = "";
			url += REPO_ADDR;
			url += repo_rule;

			HINTERNET file = InternetOpenUrlA(session, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
			if (!file) {
				return false;
			}

			std::string output_path = "./rules/";
			output_path += repo_rule;
			std::ofstream out_file(output_path, std::ios::binary);
			if (!out_file.is_open()) {
				InternetCloseHandle(file);
				return false;
			}

			char tmp_buffer[4096];
			memset(tmp_buffer, 0, 4096);
			DWORD bytes_read = 0;

			while (InternetReadFile(file, tmp_buffer, 4096, &bytes_read) && bytes_read > 0) {
				out_file.write(tmp_buffer, bytes_read);
			}

			out_file.close();
			InternetCloseHandle(file);
		}

		return true;
	}

	void disconnect() {
		if (connection) {
			InternetCloseHandle(connection);
			connection = nullptr;
		}

		if (session) {
			InternetCloseHandle(session);
			session = nullptr;
		}
	}

	~HttpClient() {
		disconnect();
	}
};

class AVEngine {
private:
	std::vector<DWORD> process_list;
	std::vector<DWORD> malicious_processes;

	DWORD get_integrity_level(HANDLE token) {
		DWORD size = 0;
		GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
		TOKEN_MANDATORY_LABEL* token_label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(malloc(size));
		memset(token_label, 0, size);

		GetTokenInformation(token, TokenIntegrityLevel, token_label, size, &size);

		DWORD integrity_level = *GetSidSubAuthority(token_label->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(token_label->Label.Sid)) - 1);

		free(token_label);
		return integrity_level;
	}

	bool memory_buffer_search(unsigned char* parent_buffer, size_t parent_buffer_size, unsigned char* child_buffer, size_t child_buffer_size) {
		if (!parent_buffer || !child_buffer || child_buffer_size == 0 || parent_buffer_size < child_buffer_size) {
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
	bool update_process_list() {
		HANDLE self_token;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self_token)) {
			return false;
		}

		DWORD self_token_label = get_integrity_level(self_token);
		CloseHandle(self_token);

		HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (process_snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(process_entry);

		if (!Process32First(process_snapshot, &process_entry)) {
			CloseHandle(process_snapshot);
			return false;
		}

		do {
			HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_entry.th32ProcessID);
			if (!process) {
				continue;
			}

			HANDLE token;
			if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
				CloseHandle(process);
				continue;
			}

			DWORD process_token_label = get_integrity_level(token);
			// if (process_token_label <= self_token_label) {
			if (process_token_label < self_token_label) { // Try less, not equal
				process_list.push_back(process_entry.th32ProcessID);
			}

			CloseHandle(token);
			CloseHandle(process);
		} while (Process32Next(process_snapshot, &process_entry));

		CloseHandle(process_snapshot);
		return true;
	}

	void scan_processes(std::vector<std::string> &rules) {
		for (const auto& pid : process_list) {
			HANDLE process = OpenProcess(0, FALSE, pid);
			if (process == INVALID_HANDLE_VALUE) {
				continue;
			}

			MEMORY_BASIC_INFORMATION memory_basic_info{};
			unsigned char* tmp_buffer = reinterpret_cast<unsigned char*>(malloc(32768));
			if (tmp_buffer == NULL) {
				continue;
			}
			memset(tmp_buffer, 0, 32768);
			uintptr_t address = 0;

			while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory_basic_info, sizeof(memory_basic_info)) == sizeof(memory_basic_info)) {
				if (memory_basic_info.State == MEM_COMMIT) {
					if (!(memory_basic_info.Protect & PAGE_GUARD) && !(memory_basic_info.Protect && PAGE_NOACCESS)) {
						if (memory_basic_info.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
							uintptr_t region_base = reinterpret_cast<uintptr_t>(memory_basic_info.BaseAddress);
							SIZE_T region_size = memory_basic_info.RegionSize;
							SIZE_T offset = 0;

							while (offset < region_size) {
								SIZE_T to_read = min(sizeof(tmp_buffer), region_size - offset);
								SIZE_T bytes_read = 0;

								if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(region_base + offset), tmp_buffer, to_read, &bytes_read)) {
									for (const auto& rule : rules) {
										if (rule.length() > 4 && rule.substr(rule.length() - 4) != ".bin") {
											continue;
										}

										std::string rule_file_path = "";
										rule_file_path += "./rules/";
										rule_file_path += rule;

										std::ifstream rule_file(rule_file_path, std::ios::binary);
										if (!rule_file.is_open()) {
											continue;
										}

										std::uintmax_t rule_file_size = std::filesystem::file_size(rule_file_path);

										unsigned char* rule_buffer = reinterpret_cast<unsigned char*>(malloc(rule_file_size));
										memset(rule_buffer, 0, rule_file_size);

										rule_file.read(reinterpret_cast<char*>(rule_buffer), rule_file_size);
										rule_file.close();

										bool malicious = memory_buffer_search(tmp_buffer, 32768, rule_buffer, rule_file_size);
										free(rule_buffer);

										if (!malicious) {
											continue;
										}

										malicious_processes.push_back(pid);
									}
								}

								memset(tmp_buffer, 0, 32768);
								offset += to_read;
							}
						}
					}
				}
			}

			CloseHandle(process);
			free(tmp_buffer);
		}

		for (const auto& pid : malicious_processes) {
			HANDLE process = OpenProcess(0, false, pid);
			TerminateProcess(process, -1);
			CloseHandle(process);
		}
	}
};

bool enumerate_local_rules(std::vector<std::string> &file_list) {
	WIN32_FIND_DATAA found_data;
	HANDLE find;

	std::string search_path = "./rules/";
	find = FindFirstFileA(search_path.c_str(), &found_data);
	if (find == INVALID_HANDLE_VALUE) {
		return false;
	}

	while (FindNextFileA(find, &found_data) != 0) {
		std::string filename = found_data.cFileName;

		if (filename != "." && filename != "..") {
			if ((found_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				file_list.push_back(filename);
			}
		}
	}
}
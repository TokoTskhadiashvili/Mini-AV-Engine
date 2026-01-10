#include "httpclient.hpp"
#include "avengine.hpp"
#include "parser.hpp"

#include <thread>

bool ConnectServer(HINTERNET& session, HINTERNET& connection, std::string& host, std::string& user_agent);
bool DisconnectServer(HINTERNET& session, HINTERNET& connection);
bool SetCookieHTTP(std::string& url, std::string& name, std::string& value);

void UpdateIndicators(HINTERNET& connection, std::vector<std::string>& server_indicators);
void UpdateIndicatorList(HINTERNET& connection, std::vector<std::string> server_indicators, std::vector<std::string> local_indicators);

void AlertServer(HINTERNET& connection, std::string& message);

void UpdateProcessList(std::map<DWORD, bool>& process_list);
void ScanProcesses(HINTERNET& connection, std::vector<std::string>& local_indicators, std::map<DWORD, bool>& process_list, void (*AlertServer)(HINTERNET&, std::string&));
void ScanFiles(HINTERNET& connection, std::vector<std::string>& local_indicators, std::vector<std::string>& target_directories, void (*AlertServer)(HINTERNET&, std::string&));

std::map<std::string, std::string> ParseConfig(std::string& path);

std::vector<std::string> _GetLocalIndicators(std::string& path) {
	std::vector<std::string> indicators;
	WIN32_FIND_DATAA data;
	HANDLE find;

	find = FindFirstFileA(path.c_str(), &data);
	if (find == INVALID_HANDLE_VALUE) {
		return {};
	}

	while (FindNextFileA(find, &data) != 0) {
		std::string filename = data.cFileName;

		if ((filename != "." && filename != "..") && ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
			indicators.push_back(filename);
		}
	}
}

int main(void) {
	std::map<DWORD, bool> process_list;

	std::vector<std::string> server_indicators;
	std::vector<std::string> local_indicators;

	std::vector<std::string> target_directories;
	std::vector<std::string> file_list_mal;

	HINTERNET session, connection = nullptr;

	/* Configuration */
	std::string user_agent = USER_AGENT;
	std::string server_addr;
	std::string uuid;
	unsigned int timeout = 0;

	/* Parse Configuration */
	const std::map<std::string, std::string> config = ParseConfig(std::string("config.cfg"));
	
	bool server_addr_set = false;
	bool uuid_set = false;
	bool timeout_set = false;

	for (const auto& [raw_key, raw_value] : config) {
		std::string key = _TrimString(raw_key);
		std::string value = _TrimString(raw_value);

		if (key == "SERVER_ADDR" && server_addr_set == false) {
			server_addr = value;
			server_addr_set = true;
		}
		if (key == "UUID" && uuid_set == false) {
			uuid = value;
			uuid_set = true;
		}
		if (key == "TIMEOUT" && timeout_set == false) {
			timeout = atoi(value.c_str());
			timeout_set = true;
		}
	}

	/* Connect to the server */
	if (!ConnectServer(session, connection, server_addr, user_agent)) {
		return -1;
	}

	std::string cookie_url = "https://" + server_addr + ":8080/";
	if (!SetCookieHTTP(cookie_url, std::string("UUID"), uuid)) {
		InternetCloseHandle(connection);
		InternetCloseHandle(session);
		
		return -1;
	}

	UpdateIndicatorList(connection, server_indicators, local_indicators);
	UpdateIndicators(connection, server_indicators);

	/* Start Process & File scanning */
	while (1) {
		std::thread process_scanner(
			ScanProcesses,
			std::ref(connection),
			std::ref(local_indicators),
			std::ref(process_list),
			AlertServer
		);
		std::thread file_scanner(
			ScanFiles,
			std::ref(connection),
			std::ref(local_indicators),
			std::ref(target_directories),
			AlertServer
		);

		process_scanner.join();
		file_scanner.join();

		KillAllMalicious(process_list);
		Sleep(timeout);
	}

	DisconnectServer(session, connection);
	return 0;
}

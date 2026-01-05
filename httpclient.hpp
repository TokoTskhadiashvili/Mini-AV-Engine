#pragma once

#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include <Windows.h>
#include <Wininet.h>

#pragma comment(lib, "wininet.lib")

class HttpClient {
private:
	HINTERNET session = nullptr;
	HINTERNET connection = nullptr;
	DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;

	std::vector<std::string> server_rules;
	std::vector<std::string> local_rules;

public:
	void set_local_rules(std::vector<std::string>& rules) {

	}

	bool connect(std::string& host, std::string& user_agent) {
		session = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (!session) {
			return false;
		}

		connection = InternetConnectA(session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, "", "", INTERNET_SERVICE_HTTP, 0, 0);
		if (!connection) {
			InternetCloseHandle(session);
			return false;
		}

		return true;
	}

	/* Use right after connect(); */
	bool set_cookie(std::string& url, const std::string& name, std::string& value) {
		std::string cookie = name + "=" + value + "; path=/";
		return InternetSetCookieA(url.c_str(), nullptr, cookie.c_str()) == true;
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

	bool fetch_all_rules(std::string& host) {
		std::string data;
		HINTERNET file = InternetOpenUrlA(session, host.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
		if (!file) {
			return false;
		}

		char buffer[4096];
		memset(buffer, 0, 4096);
		DWORD read = 0;

		while (InternetReadFile(file, buffer, 4096, &read) && read > 0) {
			data.append(buffer, read);
		}

		InternetCloseHandle(file);

		if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xEF && static_cast<unsigned char>(data[1]) == 0xBB && static_cast<unsigned char>(data[2]) == 0xBF) {
			data.erase(0, 3);
		}

		std::istringstream iss(data);
		std::string line;

		while (std::getline(iss, line)) {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}

			if (!line.empty()) {
				server_rules.push_back(line);
			}
		}

		return true;
	}

	void filter_rules() {
		server_rules.erase(
			std::remove_if(
				server_rules.begin(),
				server_rules.end(),
				[&](const std::string& rule) {
					return std::find(local_rules.begin(), local_rules.end(), rule) != local_rules.end();
				}
			),
			server_rules.end()
		);
	}

	bool update_rules(std::string& host) {
		char buffer[4096];
		for (const auto& rule : server_rules) {
			memset(buffer, 0, 4096);
			std::string url = "";
			url += host;
			url += "files/rules/";
			url += rule;

			HINTERNET file = InternetOpenUrlA(session, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
			if (!file) {
				continue;
			}

			std::string write_path = "rules/";
			write_path += rule;
			std::ofstream output(write_path, std::ios::binary);
			if (!output.is_open()) {
				InternetCloseHandle(file);
				continue;
			}

			DWORD read = 0;

			while (InternetReadFile(file, buffer, 4096, &read) && read > 0) {
				output.write(buffer, read);
			}

			output.close();
			InternetCloseHandle(file);
		}

		return true;
	}

	bool alert(std::string& data) {
		if (!connection) return false;

		HINTERNET request = HttpOpenRequestA(connection, "POST", "/api/child/alert", NULL, NULL, NULL, flags, 0);
		if (!request) {
			return false;
		}

		std::string headers = "Content-Type: application/json\r\n";
		BOOL result = HttpSendRequestA(request, headers.c_str(), headers.size(), const_cast<char*>(data.data()), data.size());
		if (!result) {
			InternetCloseHandle(request);
			return false;
		}

		char buffer[4096];
		memset(buffer, 0, 4096);
		DWORD read = 0;
		std::string response;

		while (InternetReadFile(request, buffer, 4096, &read) && read > 0) {
			response.append(buffer, read);
		}

		InternetCloseHandle(request);
		return true;
	}

	~HttpClient() {
		disconnect();
	}
};

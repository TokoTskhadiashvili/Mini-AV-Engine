#pragma once

#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include <Windows.h>
#include <Wininet.h>

#define USER_AGENT "Mini AV Engine 1.0"

#pragma comment(lib, "wininet.lib")

bool ConnectServer(HINTERNET& session, HINTERNET& connection, std::string& host, std::string& user_agent) {
	session = InternetOpenA(user_agent.c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!session) {
		return false;
	}

	connection = InternetConnectA(session, host.c_str(), 8080, "", "", INTERNET_SERVICE_HTTP, 0, 0);
	if (!connection) {
		return false;
	}

	return true;
}

bool DisconnectServer(HINTERNET& session, HINTERNET& connection) {
	try {
		if (connection) {
			InternetCloseHandle(connection);
			connection = nullptr;
		}

		if (session) {
			InternetCloseHandle(session);
			session = nullptr;
		}

		return true;
	}
	catch (...) {
		return false;
	}
}

bool SetCookieHTTP(std::string& url, const std::string& name, std::string& value) {
	std::string cookie = name + "=" + value + "; path=/";
	DWORD flags = INTERNET_COOKIE_HTTPONLY;

	if (!InternetSetCookieExA(url.c_str(), nullptr, cookie.c_str(), flags, 0)) {
		return false;
	}

	return true;
}

void UpdateIndicators(HINTERNET& connection, std::vector<std::string>& server_indicators) {
	size_t buffer_size = 8192;
	unsigned char* buffer = (unsigned char*)malloc(buffer_size);
	if (buffer == NULL) {
		return;
	}
	
	for (const std::string& indicator : server_indicators) {
		memset(buffer, 0, buffer_size);
		
		std::string uri = "/files/indicators/";
		uri += indicator;

		HINTERNET request = HttpOpenRequestA(connection, "GET", uri.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
		if (!request) {
			continue;
		}

		if (!HttpSendRequestA(request, NULL, 0, NULL, 0)) {
			InternetCloseHandle(request);
			continue;
		}

		std::string path = (indicator.substr(indicator.size() - 4) == ".bin") ? "indicators/bin/" : "indicators/txt/";
		path += indicator;

		std::ofstream disk_file(path, std::ios::binary);
		if (!disk_file.is_open()) {
			InternetCloseHandle(request);
			continue;
		}

		DWORD read = 0;
		while (InternetReadFile(request, buffer, buffer_size, &read) && read > 0) {
			disk_file.write((char*)buffer, read);
		}

		disk_file.close();
		InternetCloseHandle(request);
	}

	free(buffer);
	return;
}

void UpdateIndicatorList(HINTERNET& connection, std::vector<std::string> server_indicators, std::vector<std::string> local_indicators) {
	std::string data = "";
	HINTERNET request = HttpOpenRequestA(connection, "GET", "/repo.txt", NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);

	if (!request) {
		return;
	}

	size_t buffer_size = 512;
	unsigned char* buffer = (unsigned char*)malloc(buffer_size);
	if (buffer == NULL) {
		return;
	}
	memset(buffer, 0, buffer_size);
	DWORD read = 0;

	while (InternetReadFile(request, buffer, buffer_size, &read) && read > 0) {
		data.append((char*)buffer, read);
	}
	free(buffer);

	InternetCloseHandle(request);

	if (data.size() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
		data.erase(0, 3);
	}

	std::istringstream iss(data);
	std::string line;

	while (std::getline(iss, line)) {
		if (!line.empty()) {
			server_indicators.push_back(line);
		}
	}

	server_indicators.erase(
		std::remove_if(
			server_indicators.begin(),
			server_indicators.end(),
			[&](const std::string& indicator) {
				return std::find(local_indicators.begin(), local_indicators.end(), indicator) != local_indicators.end();
			}
		),
		server_indicators.end()
	);

	return;
}

void AlertServer(HINTERNET& connection, std::string& message) {
	DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
	HINTERNET request = HttpOpenRequestA(connection, "POST", "/worker/alert", NULL, NULL, NULL, flags, 0);

	DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
	InternetSetOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));

	std::string headers = "Content-Type: application/json\r\n";
	if (!HttpSendRequestA(request, headers.c_str(), headers.size(), message.data(), message.size())) {
		InternetCloseHandle(request);
		return;
	}

	size_t buffer_size = 1024;
	char* buffer = (char*)malloc(buffer_size);
	if (buffer == NULL) {
		InternetCloseHandle(request);
		return;
	}
	memset(buffer, 0, buffer_size);
	
	DWORD read = 0;
	while (InternetReadFile(request, buffer, buffer_size, &read) && read > 0) {
		continue;
	}

	free(buffer);
	InternetCloseHandle(request);
	return;
}

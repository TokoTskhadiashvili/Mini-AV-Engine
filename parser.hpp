#pragma once

#include <filesystem>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>
#include <map>

std::map<std::string, std::string> parse_config(std::string& path) {
	std::ifstream file(path);
	std::map<std::string, std::string> config;

	if (!file.is_open()) {
		return {};
	}

	std::string line;
	while (std::getline(file, line)) {
		if (line.empty() || line[0] == '#')
			continue;

		auto position = line.find('=');
		if (position == std::string::npos)
			continue;

		std::string key = line.substr(0, position);
		std::string value = line.substr(position + 1);

		config.emplace(std::move(key), std::move(value));
	}

	return config;
}
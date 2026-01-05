#include "httpclient.hpp"
#include "avengine.hpp"
#include "parser.hpp"

#define USER_AGENT "Mini AV Engine 1.0"

std::vector<std::string> get_local_rules(std::string& rules_path) {
	std::vector<std::string> local_rules;
	WIN32_FIND_DATAA found_data;
	HANDLE find;

	find = FindFirstFileA(rules_path.c_str(), &found_data);
	if (find == INVALID_HANDLE_VALUE) {
		return {};
	}

	while (FindNextFileA(find, &found_data) != 0) {
		std::string filename = found_data.cFileName;

		if (filename != "." && filename != "..") {
			if ((found_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				local_rules.push_back(filename);
			}
		}
	}

	return local_rules;
}

int main(void) {
	std::string config_path = "./config.cfg";
	std::string rules_path = "./rules/";
	std::string user_agent = USER_AGENT;
	std::string server_address;
	std::string uuid;

	std::map<std::string, std::string> config_data = parse_config(config_path);
	std::vector<std::string> local_rules = get_local_rules(rules_path);

	server_address = config_data.at("SERVER_ADDRESS");
	uuid = config_data.at("UUID");

	HttpClient hc;
	hc.connect(server_address, user_agent);
	hc.set_cookie(server_address, std::string("uuid"), uuid);

	hc.fetch_all_rules(server_address);
	hc.set_local_rules(local_rules);
	hc.filter_rules();
	hc.update_rules(server_address);

	AVEngine ave;

	return 0;
}
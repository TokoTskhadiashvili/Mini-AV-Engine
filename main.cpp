#include "main.hpp"

bool enumerate_local_rules(std::vector<std::string>& file_list);

void process_scanner(AVEngine& ave, std::vector<std::string> &local_rules) {
	while (1) {
		ave.scan_processes(local_rules);
	}
}

void file_scanner(AVEngine& ave, std::vector<std::string>& local_rules) {

}

int main(void) {
	HttpClient hc;
	AVEngine ave;

	hc.connect(REPO_ADDR, USER_AGENT);

	std::string repo_list_path = "";
	repo_list_path += REPO_ADDR;
	repo_list_path += "repo.txt";

	hc.populate_file_list(repo_list_path.c_str());

	std::vector<std::string> local_rules;
	enumerate_local_rules(local_rules);
	hc.update_rules(local_rules);

	hc.download_rules();

	std::thread process_scanner_thread(process_scanner, ave, local_rules);
	std::thread file_scanner_thread(file_scanner, ave, local_rules);

	process_scanner_thread.join();
	file_scanner_thread.join();

	return 0;
}
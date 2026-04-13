#include <libssh/libssh.h>
#include <iostream>
#include <string>

const int ATTEMPTS = 5;

int main(int argc, char* argv[]) {
    if(argc <= 1) {
        std::cerr << "Couldn't reach server" << std::endl;
        return 1;
    }

    std::string host = argv[1];
    std::string user = "userman1234";
    std::string password = "passwordpassword";

    for(int i = 0; i < ATTEMPTS; i++) {
        ssh_session session = ssh_new();
        ssh_options_set(session, SSH_OPTIONS_HOST, host.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, user.c_str());

        int code = ssh_connect(session);
        if(code != SSH_OK) {
            std::cerr << "Attempt " << (i+1) << ": Connection error: " << ssh_get_error(session) << std::endl;
            ssh_free(session);
            continue;
        }

        code = ssh_userauth_password(session, nullptr, password.c_str());
        if (code == SSH_AUTH_SUCCESS) {
            std::cout << "Attempt number " << (i+1) << ": Login succeeded" << std::endl;
        } else {
            std::cout << "Attempt number " << (i+1) << ": Login failed " << ssh_get_error(session) << std::endl;
        }

        ssh_disconnect(session);
        ssh_free(session);
    }

    return 0;
}
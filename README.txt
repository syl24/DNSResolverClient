A scaled down iterative DNS Resolver Client using UDP.

Steps to run application:

Windows:
1) Install some application to run bash on windows (E.g Git bash (https://git-scm.com/downloads), Windows Subsystem Linux (WSL, I recommend using WSL) https://docs.microsoft.com/en-us/windows/wsl/install-win10).
2) Install java and javac (Follow this guide to install java on Linux, https://www.digitalocean.com/community/tutorials/how-to-install-java-with-apt-on-ubuntu-18-04).
3) Run the command, make clean, when initially running the application or if changes are made to any of the files.
4) Run the command, make run, to run the application.

Linux:
1) Follow the above Windows steps starting from 2)

Application Commands:
1) lookup <domain-name>: domain-name is a string you are inquiring for to resolve the domain's ip address.
2) trace <on|off>: toggling on produces a trace of all the queries being sent along with the responses. Default to Off.
3) server <IP>: IP is a string which represents the root domain ip address (root server). Default to 199.7.83.42
4) dump: stdout all the contents of the cache.
5) quit: Quit the application.

Screencast link: https://asciinema.org/a/zB0FruScfbdksITzEqqd32my3?autoplay=1

Useful information on DNS:
i) https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html#fnref:hex
ii) http://www.zytrax.com/books/dns/ch15/#overview
iii) https://tools.ietf.org/html/rfc1035#page-25

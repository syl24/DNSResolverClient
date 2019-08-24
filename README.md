# DNS Resolver Client: A scaled down iterative DNS Resolver Client using UDP

**Helpful Documentation**:

* [Handwrite DNS Message](https://routley.io/posts/hand-writing-dns-messages/)

* [DNS Overview](http://www.zytrax.com/books/dns/ch15/#overview)

* [DNS RFC](https://tools.ietf.org/html/rfc1035#page-25)

**Intro**:

A scaled back iterative DNS resolver client which allows users to interact with various DNS servers to resolve domain names (E.g [google.ca](https://www.google.ca/)) into IP addresses. The DNS client supports record types A (IPV4), AAAA (IPV6), CNAME, and NS. Implemented a Depth-First-Search traversal, cache, and CNAME prediction, which optimized performance by over 50%.

[![dns gif](dns.svg)](https://asciinema.org/a/zB0FruScfbdksITzEqqd32my3?autoplay=1)

**Requirements**:

If you are using Windows, install some application to Linux or bash on windows. I highly recommend to install [WSL](https://docs.microsoft.com/en-us/windows/wsl/install-win10) to run Linux in a windows environment. To install Java and javac on Linux (Ubuntu) refer to this [documentation](https://www.digitalocean.com/community/tutorials/how-to-install-java-with-apt-on-ubuntu-18-04). Source code currently has only been tested on Linux (WSL), other platforms may behave unexpectedly.

**Running the application**:

Initially when running the application, go to the root directory of the project and run the command `make clean`, which will remove any previously compiled files. Note: you only need to run `make clean` if you are initially running the application or if changes are made to any of the files. Run the command, `make run` to run the application.

**Application Commands:**

* lookup `domain-name`: `domain-name` is a string you are inquiring for to resolve the domain's ip address.
* trace `on|off`: Toggling `on` produces a trace of all the queries being sent along with the responses. Default to `off`.
* server `IP`: `IP` is a string which represents the root domain ip address (root server). Default to 199.7.83.42
* dump: stdout all the contents of the cache.
* quit: Quit the application.

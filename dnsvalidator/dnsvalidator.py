#!/usr/bin/env python3
import concurrent.futures
import dns.resolver
import os
import random
import re
import signal
import string
import sys
import threading
import time
from typing import Set, List

from .lib.core.input import InputParser, InputHelper
from .lib.core.output import OutputHelper, Level


def rand():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(10))


def resolve():
    pass


parser = InputParser()
arguments = parser.parse(sys.argv[1:])

output = OutputHelper(arguments)
output.print_banner()
base_dns_servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

base_domains: List[str] = ["bet365.com", "telegram.com", "dev.by"]
nxdomainchecks: List[str] = ["facebook.com", "paypal.com", "google.com",
                             "bet365.com", "wikileaks.com"]

valid_servers = []
base_dns_servers_responses = {}

valid_domains_ips = {}


def resolve_address(server: str):
    # Skip if not IPv4
    valid = re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server)
    if not valid:
        output.terminal(Level.VERBOSE, server, "skipping as not IPv4")
        return

    output.terminal(Level.INFO, server, "Checking...")

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]

    # Try to resolve our positive baselines before going any further
    for nxdomaincheck in nxdomainchecks:
        # make sure random subdomains are NXDOMAIN
        try:
            positivehn = "{rand}.{domain}".format(
                rand=rand(),
                domain=nxdomaincheck
            )
            posanswer = resolver.resolve(positivehn, 'A')

            # nxdomain exception was not thrown, we got records when we shouldn't have.
            # Skip the server.
            output.terminal(Level.ERROR, server,
                            f"DNS poisoning detected, passing: {nxdomaincheck}")
            return
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            output.terminal(Level.ERROR, server,
                            "Error when checking for DNS poisoning, passing")
            return
    current_dns_responses = {}
    for base_domain in base_domains:
        answer = resolver.resolve(base_domain, 'A')
        current_dns_domain_ips = {str(rr) for rr in answer}
        current_dns_responses[base_domain] = current_dns_domain_ips

    if len(valid_domains_ips) != len(current_dns_responses):
        output.terminal(Level.REJECTED, server, "resolved domains invalid")
        return
    if valid_domains_ips == current_dns_responses:
        output.terminal(Level.ACCEPTED, server, "provided valid response")
        valid_servers.append(server)
    else:
        output.terminal(Level.REJECTED, server,
                        f"invalid response received: {base_domains_dict} {current_dns_responses}")


def main():
    # Perform resolution on each of the 'baselines'

    nx_domain_unexpected_responses_counter = {}
    for base_dns_server in base_dns_servers:
        output.terminal(Level.INFO, base_dns_server, "resolving baseline")
        baseline_server = {}

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [base_dns_server]

        # Check our baseline against this server
        try:
            resolver.resolve(arguments.rootdomain, 'A')
        except dns.exception.Timeout:
            output.terminal(Level.ERROR, base_dns_server,
                            "DNS Timeout for baseline server. Fatal")
            sys.exit(1)

        # checks for often poisoned domains
        for base_domain in base_domains:
            posanswer = resolver.resolve(base_domain, 'A')
            baseline_server[base_domain] = {str(rr) for rr in posanswer}

        for nx_domain in nxdomainchecks:
            try:
                positivehn = "{rand}.{domain}".format(
                    rand=rand(),
                    domain=nx_domain
                )
                resolver.resolve(positivehn, 'A')

                # nxdomain exception was not thrown, we got records when we shouldn't have.
                # Skip the server.
                output.terminal(Level.ERROR, base_dns_server,
                                f"check root domain, it should return nxdomain for rand subdomain: {nx_domain}")
                sys.exit(2)
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                output.terminal(Level.ERROR, base_dns_server,
                                f"Error when checking for base nx_domain, {nx_domain}")
                nx_domain_unexpected_responses_counter[nx_domain] = nx_domain_unexpected_responses_counter.setdefault(
                    nx_domain, 0)

        try:
            rand_subdomain = "{rand}.{domain}".format(
                rand=rand(),
                domain=arguments.rootdomain
            )
            resolver.resolve(rand_subdomain, 'A')
            output.terminal(Level.ERROR, base_dns_server,
                            "DNS A resolved for random subdomain => change root domain to another. Fatal")
            sys.exit(3)
        except dns.resolver.NXDOMAIN:
            pass
        except dns.exception.Timeout:
            output.terminal(Level.ERROR, base_dns_server,
                            "DNS Timeout for baseline server. Fatal")
            sys.exit(4)

        base_dns_servers_responses[base_dns_server] = baseline_server

    for domain, counter in nx_domain_unexpected_responses_counter.items():
        if counter > 1:
            output.terminal(Level.ERROR, domain, f"{domain} is not nx domain")
            sys.exit(5)

    for dns_server, base_dns_server_responses in base_dns_servers_responses.items():
        for domain, domain_ips in base_dns_server_responses.items():
            if domain not in valid_domains_ips:
                valid_domains_ips[domain] = domain_ips
            elif valid_domains_ips[domain] != domain_ips:
                output.terminal(Level.ACCEPTED,
                                f"base dns resolve domain differently {base_dns_servers_responses} {valid_domains_ips}")
                sys.exit(6)

    # loop through the list
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(arguments.threads)) as executor:
        thread = {executor.submit(
            resolve_address, server): server for server in InputHelper.return_targets(arguments)}
    output.terminal(Level.INFO, 0, "Finished. Discovered {size} servers".format(
        size=len(valid_servers)))


# Declare signal handler to immediately exit on KeyboardInterrupt


def signal_handler(signal, frame):
    os._exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    main()

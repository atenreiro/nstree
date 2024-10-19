#!/usr/bin/env python3
# nstree v1.0
# Developer: Andre Tenreiro
# Project URL: https://github.com/atenreiro/nstree
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import asyncio
import time

import dns.asyncresolver
from graphviz import Digraph

# Version information
NSTREE_VERSION = "nstree v1.0"

# Constants
ERROR_LOG_FILE = "nstree_errors.log"


def log_error(message: str) -> None:
    """Log error messages to a file."""
    with open(ERROR_LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")


async def resolve_record(
    resolver: dns.asyncresolver.Resolver, domain: str, record_type: str
):
    """
    Resolve a DNS record asynchronously and handle CNAME chains.

    Returns:
        Tuple containing:
            - answers
            - ttl
            - cname_chain
            - elapsed_time
            - success
    """
    start_time = time.time()
    cname_chain = []
    try:
        answers = await resolver.resolve(domain, record_type)
        ttl = answers.rrset.ttl

        if record_type == "CNAME":
            current_target = answers[0].target.to_text().rstrip(".")
            cname_chain.append(current_target)
            while True:
                try:
                    cname_answers = await resolver.resolve(current_target, "CNAME")
                    current_target = cname_answers[0].target.to_text().rstrip(".")
                    cname_chain.append(current_target)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    break
                except Exception as e:
                    log_error(f"Error resolving CNAME {current_target}: {e}")
                    break

        elapsed_time = (time.time() - start_time) * 1000  # ms
        return answers, ttl, cname_chain, elapsed_time, True

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        log_error(f"{type(e).__name__}: {domain} ({record_type}) - {e}")
        return None, None, [], 0, False
    except Exception as e:
        log_error(f"Unexpected error resolving {domain} ({record_type}): {e}")
        return None, None, [], 0, False


def print_hierarchy(
    domain: str,
    dns_resolvers: list,
    tld_servers: list,
    authoritative_servers: list,
    a_record: str,
    mx_record: str,
    cname_chain: list,
    times: dict,
    ttl_info: dict,
) -> None:
    """Print the DNS resolution hierarchy."""
    # DNS Resolvers
    print("🌐 DNS Resolvers:")
    for idx, server in enumerate(dns_resolvers):
        connector = "└──" if idx == len(dns_resolvers) - 1 else "├──"
        response_time = times.get("dns_resolver_time", {}).get(server, 0.0)
        print(f"   {connector} {server} (Response time: {response_time:.2f} ms)")

    # TLD DNS Servers
    print("\n   ↳ TLD DNS Servers:")
    for idx, server in enumerate(tld_servers):
        connector = "└──" if idx == len(tld_servers) - 1 else "├──"
        response_time = times.get("tld_time", {}).get(server, 0.0)
        print(f"      {connector} {server} (Response time: {response_time:.2f} ms)")

    # Authoritative DNS Servers
    print("\n         ↳ Authoritative DNS Servers:")
    for idx, server in enumerate(authoritative_servers):
        connector = "└──" if idx == len(authoritative_servers) - 1 else "├──"
        response_time = times.get("authoritative_time", {}).get(server, 0.0)
        print(f"            {connector} {server} (Response time: {response_time:.2f} ms)")

    # A Record
    if a_record:
        print(f"\n               ↳ A Record:")
        print(
            f"                  └── {a_record} (Response time: {times.get('a_time', 0.0):.2f} ms, TTL: {ttl_info.get('a_ttl', 'N/A')} seconds)"
        )

    # MX Record
    if mx_record:
        print(f"\n               ↳ MX Record:")
        print(
            f"                  └── {mx_record} (Response time: {times.get('mx_time', 0.0):.2f} ms, TTL: {ttl_info.get('mx_ttl', 'N/A')} seconds)"
        )

    # CNAME Chain
    if cname_chain:
        print(f"\n               ↳ CNAME Chain:")
        for idx, cname in enumerate(cname_chain):
            connector = "└──" if idx == len(cname_chain) - 1 else "├──"
            print(f"                  {connector} {cname}")

    print("\n+------------------------------+")
    print("| ✔️  DNS Resolution Completed  |")
    print("+------------------------------+")


async def resolve_dns_chain(
    domain: str,
    record_types: list,
    resolver: dns.asyncresolver.Resolver,
    export: bool,
) -> None:
    """Resolve DNS records for a single domain and optionally export the results."""
    print(f"\nResolving DNS chain for: {domain}\n")
    total_start_time = time.time()

    # Step 1: Measure DNS Resolver Response Times
    times_dns_resolver = {}
    for server in resolver.nameservers:
        try:
            query_start = time.time()
            await resolver.resolve("google.com", "A", lifetime=5)
            response_time = (time.time() - query_start) * 1000  # ms
            times_dns_resolver[server] = response_time
        except Exception as e:
            log_error(f"Error measuring resolver {server} response time: {e}")
            times_dns_resolver[server] = 0.0

    # Step 2: Resolve TLD Servers
    tld_domain = domain.split('.')[-1]
    tld_servers = []
    times_tld = {}
    tld_answers, _, _, _, tld_success = await resolve_record(
        resolver, f"{tld_domain}.", "NS"
    )
    if tld_success and tld_answers:
        tld_servers = [str(ns).rstrip(".") for ns in tld_answers]
        for tld_server in tld_servers:
            try:
                tld_start = time.time()
                await resolver.resolve(tld_server, "A", lifetime=5)
                times_tld[tld_server] = (time.time() - tld_start) * 1000
            except Exception as e:
                log_error(f"Error measuring TLD server {tld_server} response time: {e}")
                times_tld[tld_server] = 0.0
    else:
        tld_servers = ["N/A"]
        times_tld = {"N/A": 0.0}

    # Step 3: Resolve Authoritative Servers
    authoritative_servers = []
    times_authoritative = {}
    auth_answers, _, _, _, auth_success = await resolve_record(resolver, domain, "NS")
    if auth_success and auth_answers:
        authoritative_servers = [str(ns).rstrip(".") for ns in auth_answers]
        for auth_server in authoritative_servers:
            try:
                auth_start = time.time()
                await resolver.resolve(auth_server, "A", lifetime=5)
                times_authoritative[auth_server] = (time.time() - auth_start) * 1000
            except Exception as e:
                log_error(f"Error measuring authoritative server {auth_server} response time: {e}")
                times_authoritative[auth_server] = 0.0
    else:
        authoritative_servers = ["N/A"]
        times_authoritative = {"N/A": 0.0}

    # Step 4: Resolve Records (A, MX, CNAME)
    a_record = mx_record = None
    cname_chain = []
    a_time = mx_time = 0.0
    ttl_info = {"a_ttl": None, "mx_ttl": None}

    for record_type in record_types:
        answers, ttl, cname, elapsed_time, success = await resolve_record(
            resolver, domain, record_type
        )
        if success:
            if record_type == "A":
                a_record = answers[0].address
                a_time = elapsed_time
                ttl_info["a_ttl"] = ttl
            elif record_type == "MX":
                mx_record = answers[0].exchange.to_text().rstrip(".")
                mx_time = elapsed_time
                ttl_info["mx_ttl"] = ttl
            elif record_type == "CNAME":
                cname_chain = cname

    # Compile all times
    times = {
        "dns_resolver_time": times_dns_resolver,
        "tld_time": times_tld,
        "authoritative_time": times_authoritative,
        "a_time": a_time,
        "mx_time": mx_time,
    }

    # Print the DNS resolution hierarchy
    print_hierarchy(
        domain,
        resolver.nameservers,
        tld_servers,
        authoritative_servers,
        a_record,
        mx_record,
        cname_chain,
        times,
        ttl_info,
    )

    # Calculate total execution time
    total_elapsed_time = (time.time() - total_start_time) * 1000  # ms
    print(f"\nTotal execution time: {total_elapsed_time:.2f} ms\n")

    # Export to Graphviz if requested
    if export:
        gv_filename = f"dns_resolution_{domain}.gv"
        pdf_filename = f"dns_resolution_{domain}.pdf"
        print(f"\n📁 Exporting Results:\n   Files will be saved as '{gv_filename}' and '{pdf_filename}'")

        diagram = Digraph(comment=f'DNS Resolution for {domain}')
        diagram.node("Root", "DNS Resolvers")

        # Add TLD Servers
        for tld_server in tld_servers:
            if tld_server != "N/A":
                diagram.edge("Root", tld_server, label=f"{times['tld_time'].get(tld_server, 0.0):.2f} ms")

        # Add Authoritative Servers
        for auth_server in authoritative_servers:
            if auth_server != "N/A":
                diagram.edge("Root", auth_server, label=f"{times['authoritative_time'].get(auth_server, 0.0):.2f} ms")

        # Add A Record
        if a_record:
            diagram.node(a_record, f"A: {a_record}\nTTL: {ttl_info['a_ttl']}s")
            for auth_server in authoritative_servers:
                if auth_server != "N/A":
                    diagram.edge(auth_server, a_record, label=f"{times['a_time']:.2f} ms")

        # Add MX Record
        if mx_record:
            diagram.node(mx_record, f"MX: {mx_record}\nTTL: {ttl_info['mx_ttl']}s")
            for auth_server in authoritative_servers:
                if auth_server != "N/A":
                    diagram.edge(auth_server, mx_record, label=f"{times['mx_time']:.2f} ms")

        # Add CNAME Chain
        previous_node = None
        for cname in cname_chain:
            diagram.node(cname, f"CNAME: {cname}")
            if previous_node:
                diagram.edge(previous_node, cname)
            else:
                for auth_server in authoritative_servers:
                    if auth_server != "N/A":
                        diagram.edge(auth_server, cname, label="CNAME")
            previous_node = cname

        # Render the diagram
        try:
            diagram.render(filename=gv_filename, format="pdf", cleanup=True)
            print(f"✅ Graphviz diagram saved as '{gv_filename}' and '{pdf_filename}'")
        except Exception as e:
            log_error(f"Error exporting Graphviz diagram: {e}")
            print(f"❌ Failed to export Graphviz diagram. Check '{ERROR_LOG_FILE}' for details.")


async def resolve_multiple_domains(
    domains: list, record_types: list, custom_resolver: str = None, export: bool = False
) -> None:
    """Handle DNS resolution for multiple domains concurrently."""
    resolver = dns.asyncresolver.Resolver()
    if custom_resolver:
        resolver.nameservers = [custom_resolver]

    # Print resolver message once
    if custom_resolver:
        print(f"Using custom resolver: {custom_resolver}")
    else:
        print("Using system's default resolver.")

    tasks = [
        resolve_dns_chain(domain, record_types, resolver, export) for domain in domains
    ]
    await asyncio.gather(*tasks)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            f"{NSTREE_VERSION} - DNS Resolution Tool with Enhanced Features\n"
            "Developer: Andre Tenreiro\n"
            "Project URL: https://github.com/atenreiro/nstree"
        )
    )
    parser.add_argument(
        "domains", metavar="D", type=str, nargs="+", help="Domain(s) to resolve"
    )
    parser.add_argument(
        "-t",
        "--record-types",
        type=str,
        nargs="+",
        default=["A"],
        choices=["A", "MX", "CNAME", "NS", "TXT", "AAAA", "SOA", "PTR", "SRV"],
        help="DNS Record Types to query (default: A)",
    )
    parser.add_argument(
        "-r",
        "--resolver",
        type=str,
        help="Custom DNS Resolver IP (e.g., 8.8.8.8)",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export the results as a Graphviz diagram",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=NSTREE_VERSION,
        help="Show version and exit",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point of the script."""
    args = parse_arguments()

    domains = args.domains
    record_types = [rtype.upper() for rtype in args.record_types]
    custom_resolver = args.resolver
    export = args.export

    print(f"🌳 Starting DNS resolution using {NSTREE_VERSION}\n")
    print(f"Domains to resolve: {', '.join(domains)}")
    print(f"Record types: {', '.join(record_types)}")
    if export:
        print("Exporting results as Graphviz diagrams.\n")
    else:
        print()

    # Run the asynchronous resolution
    asyncio.run(resolve_multiple_domains(domains, record_types, custom_resolver, export))


if __name__ == "__main__":
    main()

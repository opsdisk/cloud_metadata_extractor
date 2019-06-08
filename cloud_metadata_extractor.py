#!/usr/bin/env python

# Standard Python libraries.
import argparse
import concurrent.futures
import json
import logging
import random
import sys
import time
import urllib

# from urllib.parse import urlparse

# Third party Python libraries.
import iplib
import requests
import dns.resolver
import dns.reversename

# https://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logging
ROOT_LOGGER = logging.getLogger("metadata")
# ISO8601 datetime format by default.
LOG_FORMATTER = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s")


# Populate random User-Agent list.
with open("user_agents.txt") as fh:

    RANDOM_USER_AGENTS = []

    for line in fh:
        RANDOM_USER_AGENTS.append(line.strip())


def retrieve_azure_cloud_ips(
    azure_json_url="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20190520.json",
):
    """Extracts the cloud IP ranges from the .json file found here:

    https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20190520.json
    https://blogs.msdn.microsoft.com/nicole_welch/2017/02/azure-ip-ranges/
    """

    ROOT_LOGGER.info(f"Retrieving Azure cloud IP range json file from: {azure_json_url}")

    response = requests.get(azure_json_url, verify=True)

    if response.status_code != requests.codes.ok:
        ROOT_LOGGER.info(f"Error retrieving json file from : {azure_json_url}")
        return None

    json_data = response.json()

    ROOT_LOGGER.info(f"Extracting the Azure cloud IP ranges.")

    ip_ranges = []

    for x in json_data["values"]:
        if x["name"] == "AzureCloud":
            for ip_range in x["properties"]["addressPrefixes"]:
                ip_ranges.append(ip_range)

    if ip_ranges:
        with open("azure_cloud_ip_networks.txt", "w") as fh:
            for ip_range in ip_ranges:
                fh.write(f"{ip_range}\n")

    return ip_ranges


def retrieve_amazon_public_ec2_ipv4_ranges(write_to_disk=True):
    """Retrieve the IPv4 ranges for Amazon's public EC2."""

    ROOT_LOGGER.info("Retrieving the IPv4 ranges for Amazon's public EC2.")

    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    response = requests.get(url, verify=True)

    ip_prefix_list = []

    if response.status_code == 200:
        json_data = response.json()["prefixes"]

        for prefix in json_data:
            if "ipv6_prefix" in prefix:
                continue

            if prefix["service"] == "EC2":
                ip_prefix = prefix["ip_prefix"]
                ip_prefix_list.append(ip_prefix)

    ip_prefix_list.sort()

    if write_to_disk and ip_prefix_list:
        with open("amazon_public_ec2_ip_ranges.txt", "w") as fh:
            for prefix in ip_prefix_list:
                fh.write(f"{prefix}\n")

    return ip_prefix_list


def convert_dotted_quad_to_other_formats(dotted_quad_ip):
    """Convert a dotted quad IP address into other formats."""

    other_formats = {
        "ip_hex": iplib.convert(dotted_quad_ip, notation=iplib.IP_HEX),
        "ip_bin": iplib.convert(dotted_quad_ip, notation=iplib.IP_BIN),
        "ip_oct": iplib.convert(dotted_quad_ip, notation=iplib.IP_OCT),
        "ip_dec": iplib.convert(dotted_quad_ip, notation=iplib.IP_DEC),
    }

    return other_formats


def retrieve_ip_port_pairs_from_file(ip_port_pairs_file):
    """Retrieve the IP:PORT pairs from a file."""

    ROOT_LOGGER.info(f"Retrieving the IP:PORT pairs from file: {ip_port_pairs_file}")

    ip_ports = []

    with open(ip_port_pairs_file, "r") as fh:
        for line in fh:
            ip_ports.append(line.strip())

    return ip_ports


def get_timestamp():
    """Retrieve a pre-formated datetimestamp."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)

    return timestamp


# def fetch_all_aws_endpoint_data_urllib(base_path, base_url="http://169.254.169.254"):
#     """Given a base path, recursively fetch 'key-value' pairs from the pseudo dictionary structure.
#     Ideally, a json object would be returned by AWS.  value_dict has to be defined outside of the function,
#     since the function is called recursively.  This function utilizes the builtin urllib library
#     instead of being dependent on an external library such as requests.

#     Returns a dictionary with the full path (key) and the values.

#     #TODO Add header and proxy configuration info.
#     """

#     # Original request to discover endpoints.
#     response = urllib.request.urlopen(f"{base_url}{base_path}")

#     # String is returned, split endpoints on new lines.
#     endpoints = response.read().decode("utf-8").split("\n")

#     for endpoint in endpoints:

#         try:
#             # Found a key to query to retrieve the value.
#             if not endpoint.endswith("/"):

#                 # Build new endpoint.
#                 value_path = f"{base_path}{endpoint}"

#                 # "/latest/meta-data/public-keys/" endpoint is a little tricky.
#                 # Does not retrieve the actual key name yet.
#                 if base_path == "/latest/meta-data/public-keys/":
#                     key_slot = 0
#                     value_path = f"{base_path}{key_slot}/openssh-key"
#                     response = urllib.request.urlopen(f"{base_url}{value_path}")

#                     # Keep incrementing ssh key index until they have all been found.
#                     while response.status == 200:
#                         value = response.read().decode("utf-8")
#                         value_dict[value_path] = value
#                         print(f"{value_path}\t{value}")

#                         # Assume there's another key index and try to retrieve it.
#                         key_slot += 1
#                         value_path = f"{base_path}{key_slot}/openssh-key"
#                         print(f"trying:{base_url}{value_path}")
#                         response = urllib.request.urlopen(f"{base_url}{value_path}")

#                 else:
#                     response = urllib.request.urlopen(f"{base_url}{value_path}")
#                     value = response.read().decode("utf-8")
#                     value_dict[value_path] = value
#                     print(f"{value_path}\t{value}")

#             # A child path exists.
#             else:
#                 new_base_path = base_path + endpoint
#                 # Be sure to pass any headers and proxies to the next fetch_all_aws_endpoint_data_urllib() function call.
#                 fetch_all_aws_endpoint_data_urllib(new_base_path)

#         except Exception as e:
#             print(f"Exception: {e}")

#     return value_dict


def fetch_all_aws_endpoint_data(base_path, headers={}, proxies={}, base_url="http://169.254.169.254"):
    """Given a base path, recursively fetch 'key-value' pairs from the pseudo dictionary structure.
    Ideally, a json object would be returned by AWS.  value_dict has to be defined outside of the function.

    Returns a dictionary with the full path (key) and the values.
    """

    # Original request to discover endpoints.
    response = requests.get(f"{base_url}{base_path}", headers=headers, proxies=proxies, verify=False, timeout=5.0)

    # String is returned, split endpoints on new lines.
    endpoints = response.text.split("\n")

    for endpoint in endpoints:

        # Found a key to query to retrieve the value.
        if not endpoint.endswith("/"):

            # Build new endpoint.
            value_path = f"{base_path}{endpoint}"

            # "/latest/meta-data/public-keys/" endpoint is a little tricky.
            # Does not retrieve the actual key name yet.
            if base_path == "/latest/meta-data/public-keys/":

                key_slot = 0
                value_path = f"{base_path}{key_slot}/openssh-key"
                response = requests.get(
                    f"{base_url}{value_path}", headers=headers, proxies=proxies, verify=False, timeout=5.0
                )

                # Keep incrementing ssh key index until they have all been found.
                # Pull back a max of 5 keys.
                while response.status_code == 200 and (key_slot < 5):
                    value = response.text
                    value_dict[value_path] = value
                    print(f"{value_path}\t{value}")

                    # Assume there's another key index and try to retrieve it.
                    key_slot += 1
                    value_path = f"{base_path}{key_slot}/openssh-key"
                    response = requests.get(
                        f"{base_url}{value_path}", headers=headers, proxies=proxies, verify=False, timeout=5.0
                    )

            else:
                response = requests.get(
                    f"{base_url}{value_path}", headers=headers, proxies=proxies, verify=False, timeout=5.0
                )

                if response.status_code == 200:
                    value = response.text
                    value_dict[value_path] = value
                    print(f"{value_path}\t{value}")

        # A child path exists.
        else:
            new_base_path = base_path + endpoint
            # Be sure to pass any headers and proxies to the next fetch_all_aws_endpoint_data() function call.
            fetch_all_aws_endpoint_data(new_base_path, headers, proxies)

    return value_dict


def concurrent_futures_load_url_azure(proxy_target):
    """Retrieve a single page and report the URL and contents for Azure endpoints."""

    print("Functionality will be released soon.")

    return None


def concurrent_futures_load_url_digital_ocean(proxy_target):
    """Retrieve a single page and report the URL and contents for Digital Ocean endpoints."""

    print("Functionality will be released soon.")

    return None


def concurrent_futures_load_url_aws(
    aws_retrieve_all_dynamic_data, aws_retrieve_all_meta_data, aws_retrieve_user_data, proxy_target
):
    """Retrieve a single page and report the URL and contents for AWS endpoints."""

    print("Functionality will be released soon.")

    return None


def async_request(
    aws_retrieve_all_dynamic_data,
    aws_retrieve_all_meta_data,
    aws_retrieve_user_data,
    provider,
    proxy_targets,
    randomize_user_agent=True,
    max_workers=8,
):
    """Make asynchronous requests based off a list of URLs"""

    print("Functionality will be released soon.")

    return None


def main(aws_retrieve_all_dynamic_data, aws_retrieve_all_meta_data, aws_retrieve_user_data, provider, ip_port_pairs):

    # Request all the data.
    all_data = async_request(
        aws_retrieve_all_dynamic_data, aws_retrieve_all_meta_data, aws_retrieve_user_data, provider, ip_port_pairs
    )

    # Only write if data exists.
    if all_data:

        # Write results to file.
        results_file = f"metaproxy_check_results_{get_timestamp()}.json"

        ROOT_LOGGER.info(f"Writing results to file: {results_file}")

        with open(results_file, "w") as fh:
            json.dump(all_data, fh)

    else:
        ROOT_LOGGER.info("No data found")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Cloud Metadata Extractor")

    parser.add_argument(
        "-aws-dynamic",
        dest="aws_retrieve_all_dynamic_data",
        action="store_true",
        default=False,
        help="Recursively retrieve AWS data from /latest/dynamic-data/ endpoint.  Default: False",
    )
    parser.add_argument(
        "-aws-meta",
        dest="aws_retrieve_all_meta_data",
        action="store_true",
        default=False,
        help="Recursively retrieve AWS data from /latest/meta-data/ endpoint.  Default: False",
    )
    parser.add_argument(
        "-aws-user",
        dest="aws_retrieve_user_data",
        action="store_true",
        default=False,
        help="Retrieve AWS data from /latest/user-data/ endpoint.  Default: False",
    )
    parser.add_argument(
        "-i", dest="ip_port_pairs_file", action="store", required=False, help="File with the IP:PORT pairs to test."
    )
    parser.add_argument(
        "-m",
        dest="min_ip_port_pairs_index",
        action="store",
        type=int,
        default=0,
        required=False,
        help="Minimum index to start at in 'ip_port_pairs' if it is known.  Default: 0",
    )
    parser.add_argument(
        "-p", dest="provider", action="store", required=True, help="Cloud provider (aws, azure, digital_ocean)."
    )
    parser.add_argument(
        "-r",
        dest="retrieve_cloud_ips",
        action="store_true",
        default=False,
        help="Retrieve cloud provider IP ranges and write to a file.  Provider specified with -p.",
    )
    parser.add_argument(
        "-s", dest="single_ip_port_pair", action="store", required=False, help="Provide a singe IP:PORT pair to test."
    )
    parser.add_argument("-v", dest="verbosity", action="store", type=int, default=4, required=False, help="Verbosity 1-5.  Default: 4.")
    parser.add_argument(
        "-x",
        dest="max_ip_port_pairs_index",
        action="store",
        type=int,
        required=False,
        help="Maximum index to start at in 'ip_port_pairs' if it is known.",
    )

    args = parser.parse_args()

    provider = args.provider.lower()

    # Assign log level.
    ROOT_LOGGER.setLevel((6 - args.verbosity) * 10)

    # Setup file logging.
    log_file_handler = logging.FileHandler(f"{provider}.log")
    log_file_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(log_file_handler)

    # Setup console logging.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(LOG_FORMATTER)
    ROOT_LOGGER.addHandler(console_handler)

    # List of providers.
    cloud_providers = ["aws", "azure", "digital_ocean"]

    if args.provider not in cloud_providers:
        print(f"{args.provider} is not a valid cloud provider.  Must be one of {cloud_providers}")
        sys.exit(1)

    # Retrieve cloud IPs.
    if args.retrieve_cloud_ips:

        if provider == "aws":
            retrieve_amazon_public_ec2_ipv4_ranges()

        elif provider == "azure":
            retrieve_azure_cloud_ips()

        sys.exit(1)

    if args.single_ip_port_pair:
        # Convert string to list.
        ip_port_pairs = args.single_ip_port_pair.split()

    else:
        ip_port_pairs = retrieve_ip_port_pairs_from_file(args.ip_port_pairs_file)

        # If specified, ensure max_ip_port_pairs_index isn't larger than the size of the list.
        if args.max_ip_port_pairs_index:

            ip_port_pairs_length = len(ip_port_pairs)

            if ip_port_pairs_length < args.max_ip_port_pairs_index:
                ROOT_LOGGER.error(f"You must choose a max_ip_port_pairs_index <= to {ip_port_pairs_length}")
                sys.exit(1)

            # fmt:off
            ip_port_pairs = ip_port_pairs[args.min_ip_port_pairs_index:(args.max_ip_port_pairs_index + 1)]
            # fmt:on

    start_time = get_timestamp()
    ROOT_LOGGER.info(f"Initiation timestamp: {start_time}")

    # main(args.aws_retrieve_all_dynamic_data, args.aws_retrieve_all_meta_data, provider, ip_port_pairs)
    main(
        args.aws_retrieve_all_dynamic_data,
        args.aws_retrieve_all_meta_data,
        args.aws_retrieve_user_data,
        provider,
        ip_port_pairs,
    )

    completion_time = get_timestamp()
    ROOT_LOGGER.info(f"Completion timestamp: {completion_time}")
    # print(f"Total time: {completion_time - start_time}")

    ROOT_LOGGER.info("Done!")

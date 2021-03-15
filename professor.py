#!/usr/env/python3
import requests
import argparse
import os

from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from typing import Dict, List

target_tags = [
    'link',
    'script'
]

security_headers = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Permissions-Policy'
]

security_headers_found = []
security_headers_found_items = {}

security_headers_missing = []

redirect = []

request_headers = []


def args_parse():

    parse = argparse.ArgumentParser()

    parse.add_argument('-u', '--url', help="Url", required=True)
    parse.add_argument(
        '-r', '--request', help="Show request headers", action='store_true')
    parse.add_argument(
        '-c', '--code', help="Print tags innter text", action='store_true')
    parse.add_argument(
        '-d', '--download', help="Download remote libs, must be a path", default=None)
    return parse.parse_args()


def outout(items: List, headers: Dict):

    global show_request_headers

    domains = set()

    print("\n== Scan Results ==".title())
    print("{:10} {:8} {:8} {:25} {:10} ".format(
        'Tag', 'Download', 'Scheme', 'Domain', 'Path'))

    for i in items:

        if i['domain']:
            domains.add(i['domain'])

        print("{tag:10} {download:8} {scheme:8} {domain:25} {link:10}".format(**i))

        if show_code:
            print('#' * 50, 'CODE', '#' * 50)
            print(i['code'])
            print("\n")

    print("\n== Total Domains used: ({}) ==".format(len(domains)))
    for d in domains:
        if not d:
            continue
        print(d)

    if show_request_headers:
        print("\nrequest headers".title())
        for i in request_headers.items():
            header_name, header_value = i

            print("{:25} {}".format(header_name, header_value))

    print("\n== raw response headers ==".title())
    for i in headers.items():
        header_name, header_value = i

        print("{:25} {}".format(header_name, header_value))

    print("\n== Information ==".title())
    print("Url {}".format(url))
    print("Scan Date: {}".format(scan_start))
    print("Missing Security Headers: ({})".format(
        len(security_headers_missing)))
    for i in security_headers_missing:
        print("    {}".format(i))
    print("Security Headers Found: ({})".format(len(security_headers_found)))
    for i in security_headers_found:
        print("    {}".format(i))
        for x in security_headers_found_items[i]:
            print("        {}".format(x))
    print("Number Of Redirects: ({})".format(len(redirect)))
    for i in redirect:
        print("    Code: {status} URL: {url}".format(**i))


def parse_text(text: str):

    results = []

    soup = BeautifulSoup(text, 'html.parser')

    for t in target_tags:

        tags = soup.find_all(t)

        for i in tags:

            if t == 'link':
                link = i.attrs.get('href', None)
            elif t == 'script':
                link = i.attrs.get('src', None)

            parse_url = urlparse(link)

            if link is not None:
                path = parse_url.path
                scheme = parse_url.scheme
                domain = parse_url.netloc
                download = False

                if download_path and domain:
                    download_file(link=link, filename=link, scheme=scheme)
                    download = True

            else:
                path = ""
                scheme = ""
                domain = ""
                download = False

            results.append({
                'tag': t,
                'link': path,
                'scheme': scheme,
                'domain': domain,
                'code': i,
                'download': download
            })

    return sorted(results, key=lambda x: x['domain'])


def download_file(link: str = "",
                  filename: str = "",
                  scheme: str = ""):

    if not scheme:
        link = f"https:{link}"

    filename = filename.replace("/", "#")

    try:
        response = requests.get(link)
    except Exception as e:
        return False

    filepath = os.path.join(download_path, filename)

    with open(filepath, 'w') as f:
        f.write(response.text)


def make_request(url: str):

    global show_request_headers
    global request_headers

    try:
        response = requests.get(url)

        if show_request_headers:
            request_headers = response.request.headers

        if response.history:
            for i in response.history:
                redirect.append({'status': i.status_code, 'url': i.url})

    except Exception as e:
        return "", {}

    return response.text, response.headers


def check_security_headers(headers: Dict = {}):

    global security_headers_missing
    global security_headers_found_items

    for i, v in headers.items():
        if i.title() in security_headers:

            header_values = v.strip().split(';')

            security_headers_found.append(i.title())

            _ = security_headers_found_items.setdefault(i.title(), [])

            [_.append(x.strip()) for x in header_values]

    security_headers_missing = list(
        set(security_headers) - set(security_headers_found))


def main():

    global args
    global url
    global show_code
    global download_path
    global scan_start
    global show_request_headers

    args = args_parse()
    url = args.url
    show_code = args.code
    download_path = args.download
    show_request_headers = args.request
    scan_start = datetime.now()

    if download_path:

        if not os.path.exists(download_path):
            os.mkdir(download_path)

    text, headers = make_request(url)

    check_security_headers(headers)

    tags = parse_text(text)

    outout(items=tags, headers=headers)


if __name__ == '__main__':

    main()

import requests
import sys
import json
import argparse
import hashlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import concurrent.futures

VERBOSE = False

# Dynamic headers excluded from the level-3 hash (exact lowercase names)
SKIP_HEADERS = {'date', 'set-cookie', 'etag'}

def hash_response(url, timeout=4):
    """
    Hash the HTTP response of a given URL at 3 levels of detail.

    Args:
        url (str): The URL to request and hash
        timeout (int): Request timeout in seconds

    Returns:
        dict: {'url': url, 'levels': {'1': ..., '2': ..., '3': ...}}, or None if request fails

    Levels:
        1: body only
        2: body + status_code + reason
        3: body + headers + status_code + reason
    """
    if not url or not isinstance(url, str):
        return None

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        response = requests.get(url,
                              allow_redirects=False,
                              timeout=timeout,
                              verify=False,
                              headers={'User-Agent': 'Mozilla/5.0'})

        # Normalize response components
        body = response.text.strip()
        status_code = str(response.status_code)
        reason = response.reason or ''

        # Sort and normalize headers, skipping dynamic ones
        header_list = []
        for header, value in sorted(response.headers.items()):
            if header.lower() in SKIP_HEADERS:
                continue
            header_list.append(f"{header}: {value}")
        headers = '\r\n'.join(header_list)

        if VERBOSE:
            print(f"URL: {url}")
            print(f"Status: {status_code} {reason}")
            print(f"Headers: {headers}")
            print(f"Body: {body[:100]}...")

        # Calculate hashes for different levels
        hashes = {
            '1': hashlib.sha256(body.encode()).hexdigest(),
            '2': hashlib.sha256(f"{body}{status_code}{reason}".encode()).hexdigest(),
            '3': hashlib.sha256(f"{body}{headers}{status_code}{reason}".encode()).hexdigest(),
        }

        return {'url': url, 'levels': hashes}

    except Exception as e:
        if VERBOSE:
            print(f"Error processing {url}: {str(e)}")
        return None

def process_urls_to_tree(urls, max_workers=10, timeout=4):
    results = []
    failed = []
    total = len(urls)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(hash_response, url, timeout): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            done += 1
            try:
                result = future.result()
            except Exception as e:
                print(f"\nError processing {url}: {str(e)}")
                result = None

            if result:
                results.append(result)
            else:
                failed.append(url)

            print(f"\rProcessed {done}/{total}", end='', flush=True)

    print()

    tree = {}
    for item in results:
        url = item["url"]
        level_1_hash = item["levels"]["1"]
        level_2_hash = item["levels"]["2"]
        level_3_hash = item["levels"]["3"]

        if level_1_hash not in tree:
            tree[level_1_hash] = {"urls": [], "children": {}}
        tree[level_1_hash]["urls"].append(url)

        if level_2_hash not in tree[level_1_hash]["children"]:
            tree[level_1_hash]["children"][level_2_hash] = {"urls": [], "children": {}}
        tree[level_1_hash]["children"][level_2_hash]["urls"].append(url)

        if level_3_hash not in tree[level_1_hash]["children"][level_2_hash]["children"]:
            tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash] = {"urls": [], "children": {}}
        tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash]["urls"].append(url)

    return tree, failed

def save_tree_json(tree, output_file='tree.json'):
    with open(output_file, 'w') as f:
        json.dump(tree, f, indent=2)

def load_urls(file_name):
    """Read URLs from a file: strip whitespace, skip blanks and # comments, dedupe."""
    urls = []
    seen = set()
    with open(file_name) as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith('#'):
                continue
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process URLs and create a hash tree visualization')
    parser.add_argument('--input', '-i', help='Input file containing URLs (one per line)')
    parser.add_argument('--output', '-o', default='tree.json', help='Output JSON file (default: tree.json)')
    parser.add_argument('--workers', '-w', '--threads', '-t', type=int, default=10, help='Number of worker threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=4, help='Request timeout in seconds (default: 4)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True

    if not args.input:
        parser.print_help()
        sys.exit(1)

    try:
        urls = load_urls(args.input)
    except Exception as e:
        print(f"Error reading input file: {str(e)}")
        sys.exit(1)

    if not urls:
        print("No URLs found in input file")
        sys.exit(1)

    print(f"Processing {len(urls)} URLs with {args.workers} workers (timeout: {args.timeout}s)")
    tree, failed = process_urls_to_tree(urls, args.workers, args.timeout)
    save_tree_json(tree, args.output)

    succeeded = len(urls) - len(failed)
    print(f"Done: {succeeded} succeeded, {len(failed)} failed")
    if failed:
        print("Failed URLs:")
        for url in failed:
            print(f"  {url}")
    print(f"Tree saved to {args.output}")

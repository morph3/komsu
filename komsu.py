import requests
import sys
import json
import argparse
import hashlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import copy
import concurrent.futures
import threading
from queue import Queue

VERBOSE = False

class Node:
    def __init__(self, hash_value, url, level):
        self.hash_value = hash_value
        self.urls = [url]
        self.size = 0
        self.children = []
        self.level = level

    def insert(self, hash_value, url, level):
        self.size += 1
        if self.size == 1:
            self.children.append(Node(hash_value, url, level))
            return
        
        for item in self.children:
            if item.hash_value == hash_value:
                item.urls.append(url)
                return

        self.children.append(Node(hash_value, url, level))
        return

    def json_dump_self(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

def hash_response(url, level=2, all_levels=True):
    """
    Hash the HTTP response of a given URL at different levels of detail.
    
    Args:
        url (str): The URL to request and hash
        level (int): The level of detail for hashing (1-3) when all_levels is False
        all_levels (bool): Whether to return hashes for all levels
    
    Returns:
        str: JSON string containing URL and hash(es), or None if request fails
        
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
                              timeout=4, 
                              verify=False,
                              headers={'User-Agent': 'Mozilla/5.0'})
        
        # Normalize response components
        body = response.text.strip()
        status_code = str(response.status_code)
        reason = response.reason or ''
        
        # Sort and normalize headers
        header_list = []
        for header, value in sorted(response.headers.items()):
            header_lower = header.lower()
            # Skip dynamic headers
            if any(skip in header_lower for skip in ['date', 'set-cookie', 'etag']):
                continue
            header_list.append(f"{header}: {value}")
        headers = '\r\n'.join(header_list)

        if VERBOSE:
            print(f"URL: {url}")
            print(f"Status: {status_code} {reason}")
            print(f"Headers: {headers}")
            print(f"Body: {body[:100]}...")

        # Calculate hashes for different levels
        hashes = {}
        
        # Level 1: body only
        if level == 1 or all_levels:
            hash_input = body
            hashes['1'] = hashlib.sha256(hash_input.encode()).hexdigest()
            
        # Level 2: body + status + reason
        if level == 2 or all_levels:
            hash_input = f"{body}{status_code}{reason}"
            hashes['2'] = hashlib.sha256(hash_input.encode()).hexdigest()
            
        # Level 3: everything
        if level == 3 or all_levels:
            hash_input = f"{body}{headers}{status_code}{reason}"
            hashes['3'] = hashlib.sha256(hash_input.encode()).hexdigest()

        result = {
            'url': url,
            'levels': hashes
        }
        
        return json.dumps(result)

    except Exception as e:
        if VERBOSE:
            print(f"Error processing {url}: {str(e)}")
        return None

def create_level_tree(file_name):
    jsons = []
    lines = open(file_name, "r").readlines()
    for line in lines:
        try:
            jsons.append(json.loads(line.strip()))
        except:
            pass

    tree = {}
    for item in jsons:
        url = item["url"]
        level_1_hash = item["levels"]["1"]
        level_2_hash = item["levels"]["2"]
        level_3_hash = item["levels"]["3"]

        if tree.get(level_1_hash) == None:
            tree[level_1_hash] = {
                "urls": [url],
                "children": {}
            }
        else:
            tree[level_1_hash]["urls"].append(url)

        if tree[level_1_hash]["children"].get(level_2_hash) == None:
            tree[level_1_hash]["children"][level_2_hash] = {
                "urls": [url],
                "children": {}
            }
        else:
            tree[level_1_hash]["children"][level_2_hash]["urls"].append(url)

        if tree[level_1_hash]["children"][level_2_hash]["children"].get(level_3_hash) == None:
            tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash] = {
                "urls": [url],
                "children": {}
            }
        else:
            tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash]["urls"].append(url)

    return tree

print_lock = threading.Lock()
tree_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def process_url(url):
    result = hash_response(url)
    if result:
        return json.loads(result)
    return None

def process_urls_to_tree(urls, max_workers=10):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(process_url, url.strip()): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                safe_print(f"Error processing {url}: {str(e)}")
    
    tree = {}
    for item in results:
        url = item["url"]
        level_1_hash = item["levels"]["1"]
        level_2_hash = item["levels"]["2"]
        level_3_hash = item["levels"]["3"]

        with tree_lock:
            if level_1_hash not in tree:
                tree[level_1_hash] = {"urls": [], "children": {}}
            tree[level_1_hash]["urls"].append(url)

            if level_2_hash not in tree[level_1_hash]["children"]:
                tree[level_1_hash]["children"][level_2_hash] = {"urls": [], "children": {}}
            tree[level_1_hash]["children"][level_2_hash]["urls"].append(url)

            if level_3_hash not in tree[level_1_hash]["children"][level_2_hash]["children"]:
                tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash] = {"urls": [], "children": {}}
            tree[level_1_hash]["children"][level_2_hash]["children"][level_3_hash]["urls"].append(url)

    return tree

def save_tree_json(tree, output_file='tree.json'):
    with open(output_file, 'w') as f:
        json.dump(tree, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process URLs and create a hash tree visualization')
    parser.add_argument('--input', '-i', help='Input file containing URLs (one per line)')
    parser.add_argument('--output', '-o', default='tree.json', help='Output JSON file (default: tree.json)')
    parser.add_argument('--workers', '-w', '--threads', '-t', type=int, default=10, help='Number of worker threads (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    if args.verbose:
        VERBOSE = True

    if not args.input:
        parser.print_help()
        sys.exit(1)

    try:
        with open(args.input) as f:
            urls = f.readlines()
    except Exception as e:
        print(f"Error reading input file: {str(e)}")
        sys.exit(1)

    tree = process_urls_to_tree(urls, args.workers)
    save_tree_json(tree, args.output)
    print(f"Tree saved to {args.output}")

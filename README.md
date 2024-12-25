# Komsu

You are a security researcher or a bug bounty hunter and you have a bunch of URLs but you don't know where to begin ? Komsu can help you.

Give your URLs to Komsu and it will generate bunch of 3-level trees based on the responses. Each level is calculated as follows,

```
Levels:
    1: body only
    2: body + status_code + reason
    3: body + headers + status_code + reason
```

Komsu at the end generates bunch of trees and visualizes them in an HTML file. You can easily eliminate a family of URLs shortening the analysis process.

![1.png](https://github.com/morph3/komsu/blob/main/1.png)

Demo,

https://morph3.blog/komsu/komsu.html

## Usage

```bash
❯ python3 komsu.py --help
usage: komsu.py [-h] [--input INPUT] [--output OUTPUT] [--workers WORKERS] [--verbose]

Process URLs and create a hash tree visualization

options:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        Input file containing URLs (one per line)
  --output OUTPUT, -o OUTPUT
                        Output JSON file (default: tree.json)
  --workers WORKERS, -w WORKERS, --threads WORKERS, -t WORKERS
                        Number of worker threads (default: 10)
  --verbose, -v         Enable verbose output
  ```

Run the script with the following command:

```bash
❯ python3 komsu.py -i urls.txt
Tree saved to tree.json
```

Serve the HTML file with `python3 -m http.server` and visit the `komsu.html`

## Files

- `komsu.py`: Main script to process URLs and generate the hash tree.
- `komsu.html`: HTML file for visualizing the generated hash tree.
- `tree.json`: Default output file for the hash tree.

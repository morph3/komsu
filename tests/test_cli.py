import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KOMSU = os.path.join(ROOT, 'komsu.py')


def run_komsu(*args, cwd=None):
    return subprocess.run(
        [sys.executable, KOMSU, *args],
        capture_output=True, text=True, cwd=cwd or ROOT, timeout=60,
    )


class TestCliArgumentHandling:
    def test_no_input_prints_help_and_exits_1(self):
        proc = run_komsu()
        assert proc.returncode == 1
        assert 'usage:' in proc.stdout

    def test_help_flag_exits_0(self):
        proc = run_komsu('--help')
        assert proc.returncode == 0
        assert '--timeout' in proc.stdout

    def test_missing_input_file_exits_1(self):
        proc = run_komsu('-i', '/nonexistent/urls.txt')
        assert proc.returncode == 1
        assert 'Error reading input file' in proc.stdout

    def test_input_with_no_urls_exits_1(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('# only comments\n\n')
        proc = run_komsu('-i', str(f))
        assert proc.returncode == 1
        assert 'No URLs found' in proc.stdout


class TestCliEndToEnd:
    def test_full_run_produces_valid_tree(self, live_server, tmp_path):
        urls = tmp_path / 'urls.txt'
        urls.write_text(
            '# comment\n'
            '\n'
            f'{live_server}/a\n'
            f'{live_server}/b\n'
            f'{live_server}/a\n'          # duplicate — must be deduped
            f'{live_server}/c\n'
            f'{live_server}/missing\n'
            'http://127.0.0.1:9/dead\n'   # unreachable — must be reported
        )
        out = tmp_path / 'tree.json'
        proc = run_komsu('-i', str(urls), '-o', str(out), '-w', '4')

        assert proc.returncode == 0
        assert 'Processing 5 URLs' in proc.stdout  # comment/blank/dup skipped
        assert 'Done: 4 succeeded, 1 failed' in proc.stdout
        assert 'http://127.0.0.1:9/dead' in proc.stdout
        assert f'Tree saved to {out}' in proc.stdout

        tree = json.loads(out.read_text())
        # /a + /b share a body, /c and /missing differ -> 3 level-1 groups
        assert len(tree) == 3
        all_urls = sorted(u for node in tree.values() for u in node['urls'])
        assert all_urls == sorted([
            f'{live_server}/a', f'{live_server}/b',
            f'{live_server}/c', f'{live_server}/missing',
        ])

    def test_default_output_is_tree_json(self, live_server, tmp_path):
        urls = tmp_path / 'urls.txt'
        urls.write_text(f'{live_server}/a\n')
        proc = run_komsu('-i', str(urls), cwd=tmp_path)
        assert proc.returncode == 0
        assert json.loads((tmp_path / 'tree.json').read_text())

    def test_timeout_flag_is_accepted(self, live_server, tmp_path):
        urls = tmp_path / 'urls.txt'
        urls.write_text(f'{live_server}/a\n')
        out = tmp_path / 'tree.json'
        proc = run_komsu('-i', str(urls), '-o', str(out), '--timeout', '10')
        assert proc.returncode == 0
        assert 'timeout: 10s' in proc.stdout

    def test_verbose_flag_produces_detail(self, live_server, tmp_path):
        urls = tmp_path / 'urls.txt'
        urls.write_text(f'{live_server}/a\n')
        out = tmp_path / 'tree.json'
        proc = run_komsu('-i', str(urls), '-o', str(out), '-v')
        assert proc.returncode == 0
        assert 'Status:' in proc.stdout

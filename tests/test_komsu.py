import hashlib
import json

import pytest
import requests

import komsu


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, body='', status_code=200, reason='OK', headers=None):
        self.text = body
        self.status_code = status_code
        self.reason = reason
        self.headers = headers or {}


def fake_get(responses):
    """Build a requests.get replacement that routes by URL. `responses` maps
    URL -> FakeResponse, or URL -> Exception instance to raise."""
    def _get(url, **kwargs):
        _get.calls.append((url, kwargs))
        result = responses[url]
        if isinstance(result, Exception):
            raise result
        return result
    _get.calls = []
    return _get


# ---------------------------------------------------------------------------
# hash_response — input validation
# ---------------------------------------------------------------------------

class TestHashResponseValidation:
    @pytest.mark.parametrize('bad_url', [None, '', 123, ['http://x'], {'u': 1}])
    def test_invalid_url_returns_none(self, bad_url):
        assert komsu.hash_response(bad_url) is None

    def test_request_exception_returns_none(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': requests.ConnectionError('refused'),
        }))
        assert komsu.hash_response('http://example.com') is None

    def test_timeout_exception_returns_none(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': requests.Timeout('too slow'),
        }))
        assert komsu.hash_response('http://example.com') is None


# ---------------------------------------------------------------------------
# hash_response — request behavior
# ---------------------------------------------------------------------------

class TestHashResponseRequest:
    def test_adds_http_scheme_when_missing(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('example.com')
        assert get.calls[0][0] == 'http://example.com'

    @pytest.mark.parametrize('url', ['http://example.com', 'https://example.com'])
    def test_preserves_existing_scheme(self, monkeypatch, url):
        get = fake_get({url: FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response(url)
        assert get.calls[0][0] == url

    def test_does_not_follow_redirects(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('http://example.com')
        assert get.calls[0][1]['allow_redirects'] is False

    def test_disables_tls_verification(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('http://example.com')
        assert get.calls[0][1]['verify'] is False

    def test_sends_user_agent(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('http://example.com')
        assert 'User-Agent' in get.calls[0][1]['headers']

    def test_default_timeout_is_4(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('http://example.com')
        assert get.calls[0][1]['timeout'] == 4

    def test_custom_timeout_is_passed(self, monkeypatch):
        get = fake_get({'http://example.com': FakeResponse()})
        monkeypatch.setattr(komsu.requests, 'get', get)
        komsu.hash_response('http://example.com', timeout=17)
        assert get.calls[0][1]['timeout'] == 17


# ---------------------------------------------------------------------------
# hash_response — hash semantics
# ---------------------------------------------------------------------------

class TestHashSemantics:
    def test_result_shape(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': FakeResponse(body='hello'),
        }))
        result = komsu.hash_response('http://example.com')
        assert result['url'] == 'http://example.com'
        assert set(result['levels'].keys()) == {'1', '2', '3'}

    def test_level1_is_sha256_of_stripped_body(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': FakeResponse(body='  hello world  \n'),
        }))
        result = komsu.hash_response('http://example.com')
        assert result['levels']['1'] == hashlib.sha256(b'hello world').hexdigest()

    def test_level2_includes_status_and_reason(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': FakeResponse(body='hello', status_code=404, reason='Not Found'),
        }))
        result = komsu.hash_response('http://example.com')
        expected = hashlib.sha256(b'hello404Not Found').hexdigest()
        assert result['levels']['2'] == expected

    def test_level3_includes_headers(self, monkeypatch):
        headers = {'Content-Type': 'text/plain', 'Server': 'test'}
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': FakeResponse(body='hello', headers=headers),
        }))
        result = komsu.hash_response('http://example.com')
        header_str = 'Content-Type: text/plain\r\nServer: test'
        expected = hashlib.sha256(f'hello{header_str}200OK'.encode()).hexdigest()
        assert result['levels']['3'] == expected

    def test_same_body_different_status_diverges_at_level2(self, monkeypatch):
        get = fake_get({
            'http://a.example': FakeResponse(body='same', status_code=200, reason='OK'),
            'http://b.example': FakeResponse(body='same', status_code=500, reason='Server Error'),
        })
        monkeypatch.setattr(komsu.requests, 'get', get)
        a = komsu.hash_response('http://a.example')
        b = komsu.hash_response('http://b.example')
        assert a['levels']['1'] == b['levels']['1']
        assert a['levels']['2'] != b['levels']['2']
        assert a['levels']['3'] != b['levels']['3']

    def test_different_headers_diverge_only_at_level3(self, monkeypatch):
        get = fake_get({
            'http://a.example': FakeResponse(body='same', headers={'Server': 'nginx'}),
            'http://b.example': FakeResponse(body='same', headers={'Server': 'apache'}),
        })
        monkeypatch.setattr(komsu.requests, 'get', get)
        a = komsu.hash_response('http://a.example')
        b = komsu.hash_response('http://b.example')
        assert a['levels']['1'] == b['levels']['1']
        assert a['levels']['2'] == b['levels']['2']
        assert a['levels']['3'] != b['levels']['3']

    @pytest.mark.parametrize('header_name', ['Date', 'date', 'Set-Cookie', 'ETag', 'etag'])
    def test_dynamic_headers_do_not_change_level3(self, monkeypatch, header_name):
        get = fake_get({
            'http://a.example': FakeResponse(body='same', headers={}),
            'http://b.example': FakeResponse(body='same', headers={header_name: 'xyz123'}),
        })
        monkeypatch.setattr(komsu.requests, 'get', get)
        a = komsu.hash_response('http://a.example')
        b = komsu.hash_response('http://b.example')
        assert a['levels']['3'] == b['levels']['3']

    def test_header_merely_containing_date_still_counts(self, monkeypatch):
        # Regression: the old substring filter dropped e.g. X-Update-Date.
        get = fake_get({
            'http://a.example': FakeResponse(body='same', headers={}),
            'http://b.example': FakeResponse(body='same', headers={'X-Update-Date': 'v1'}),
        })
        monkeypatch.setattr(komsu.requests, 'get', get)
        a = komsu.hash_response('http://a.example')
        b = komsu.hash_response('http://b.example')
        assert a['levels']['3'] != b['levels']['3']

    def test_none_reason_treated_as_empty(self, monkeypatch):
        get = fake_get({
            'http://a.example': FakeResponse(body='same', reason=None),
            'http://b.example': FakeResponse(body='same', reason=''),
        })
        monkeypatch.setattr(komsu.requests, 'get', get)
        a = komsu.hash_response('http://a.example')
        b = komsu.hash_response('http://b.example')
        assert a['levels']['2'] == b['levels']['2']

    def test_verbose_prints_response_details(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu, 'VERBOSE', True)
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': FakeResponse(body='hello'),
        }))
        komsu.hash_response('http://example.com')
        out = capsys.readouterr().out
        assert 'http://example.com' in out
        assert '200' in out
        assert 'hello' in out

    def test_verbose_prints_errors(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu, 'VERBOSE', True)
        monkeypatch.setattr(komsu.requests, 'get', fake_get({
            'http://example.com': requests.ConnectionError('refused'),
        }))
        komsu.hash_response('http://example.com')
        assert 'Error processing http://example.com' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# load_urls
# ---------------------------------------------------------------------------

class TestLoadUrls:
    def test_reads_one_url_per_line(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('http://a.com\nhttp://b.com\n')
        assert komsu.load_urls(str(f)) == ['http://a.com', 'http://b.com']

    def test_strips_whitespace(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('  http://a.com  \n\thttp://b.com\t\n')
        assert komsu.load_urls(str(f)) == ['http://a.com', 'http://b.com']

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('http://a.com\n\n   \nhttp://b.com\n')
        assert komsu.load_urls(str(f)) == ['http://a.com', 'http://b.com']

    def test_skips_comment_lines(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('# comment\nhttp://a.com\n# another\n')
        assert komsu.load_urls(str(f)) == ['http://a.com']

    def test_skips_indented_comments(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('   # indented comment\nhttp://a.com\n')
        assert komsu.load_urls(str(f)) == ['http://a.com']

    def test_dedupes_preserving_first_seen_order(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('http://b.com\nhttp://a.com\nhttp://b.com\nhttp://a.com\nhttp://c.com\n')
        assert komsu.load_urls(str(f)) == ['http://b.com', 'http://a.com', 'http://c.com']

    def test_empty_file_returns_empty_list(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('')
        assert komsu.load_urls(str(f)) == []

    def test_only_comments_returns_empty_list(self, tmp_path):
        f = tmp_path / 'urls.txt'
        f.write_text('# nothing here\n\n# really\n')
        assert komsu.load_urls(str(f)) == []

    def test_missing_file_raises(self):
        with pytest.raises(OSError):
            komsu.load_urls('/nonexistent/path/urls.txt')


# ---------------------------------------------------------------------------
# process_urls_to_tree
# ---------------------------------------------------------------------------

def routed_get(routes):
    """requests.get replacement keyed by URL path suffix."""
    def _get(url, **kwargs):
        for suffix, response in routes.items():
            if url.endswith(suffix):
                if isinstance(response, Exception):
                    raise response
                return response
        raise requests.ConnectionError(f'no route for {url}')
    return _get


class TestProcessUrlsToTree:
    def test_empty_input_returns_empty_tree(self):
        tree, failed = komsu.process_urls_to_tree([])
        assert tree == {}
        assert failed == []

    def test_identical_responses_group_together(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='same'),
            '/b': FakeResponse(body='same'),
        }))
        tree, failed = komsu.process_urls_to_tree(['http://t/a', 'http://t/b'])
        assert failed == []
        assert len(tree) == 1
        l1 = next(iter(tree.values()))
        assert sorted(l1['urls']) == ['http://t/a', 'http://t/b']
        assert len(l1['children']) == 1
        l2 = next(iter(l1['children'].values()))
        assert len(l2['children']) == 1

    def test_same_body_different_status_shares_level1_only(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='same', status_code=200, reason='OK'),
            '/b': FakeResponse(body='same', status_code=500, reason='Server Error'),
        }))
        tree, _ = komsu.process_urls_to_tree(['http://t/a', 'http://t/b'])
        assert len(tree) == 1
        l1 = next(iter(tree.values()))
        assert sorted(l1['urls']) == ['http://t/a', 'http://t/b']
        assert len(l1['children']) == 2

    def test_different_bodies_form_separate_level1_groups(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='body a'),
            '/b': FakeResponse(body='body b'),
        }))
        tree, _ = komsu.process_urls_to_tree(['http://t/a', 'http://t/b'])
        assert len(tree) == 2

    def test_failed_urls_are_reported_and_excluded(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='ok'),
            '/dead': requests.ConnectionError('refused'),
        }))
        tree, failed = komsu.process_urls_to_tree(['http://t/a', 'http://t/dead'])
        assert failed == ['http://t/dead']
        all_urls = [u for node in tree.values() for u in node['urls']]
        assert all_urls == ['http://t/a']

    def test_all_failures_produce_empty_tree(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/x': requests.ConnectionError('refused'),
            '/y': requests.Timeout('slow'),
        }))
        tree, failed = komsu.process_urls_to_tree(['http://t/x', 'http://t/y'])
        assert tree == {}
        assert sorted(failed) == ['http://t/x', 'http://t/y']

    def test_urls_without_scheme_are_handled(self, monkeypatch):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            't/a': FakeResponse(body='ok'),
        }))
        tree, failed = komsu.process_urls_to_tree(['t/a'])
        assert failed == []
        assert len(tree) == 1

    def test_progress_is_printed(self, monkeypatch, capsys):
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='ok'),
            '/b': FakeResponse(body='ok'),
        }))
        komsu.process_urls_to_tree(['http://t/a', 'http://t/b'])
        out = capsys.readouterr().out
        assert 'Processed 2/2' in out

    def test_tree_shape_matches_html_viewer_contract(self, monkeypatch, capsys):
        # komsu.html expects {hash: {urls: [...], children: {hash: {...}}}}
        monkeypatch.setattr(komsu.requests, 'get', routed_get({
            '/a': FakeResponse(body='ok'),
        }))
        tree, _ = komsu.process_urls_to_tree(['http://t/a'])
        l1 = next(iter(tree.values()))
        assert isinstance(l1['urls'], list)
        assert isinstance(l1['children'], dict)
        l2 = next(iter(l1['children'].values()))
        l3 = next(iter(l2['children'].values()))
        assert l3 == {'urls': ['http://t/a'], 'children': {}}
        # must round-trip through JSON (the viewer loads it via fetch)
        json.loads(json.dumps(tree))


# ---------------------------------------------------------------------------
# save_tree_json
# ---------------------------------------------------------------------------

class TestSaveTreeJson:
    def test_writes_valid_json(self, tmp_path):
        tree = {'abc': {'urls': ['http://a'], 'children': {}}}
        out = tmp_path / 'tree.json'
        komsu.save_tree_json(tree, str(out))
        assert json.loads(out.read_text()) == tree

    def test_overwrites_existing_file(self, tmp_path):
        out = tmp_path / 'tree.json'
        out.write_text('{"stale": true}')
        komsu.save_tree_json({'new': {}}, str(out))
        assert json.loads(out.read_text()) == {'new': {}}


# ---------------------------------------------------------------------------
# Live server (no mocking — exercises the real requests stack)
# ---------------------------------------------------------------------------

class TestLiveServer:
    def test_hash_response_against_real_server(self, live_server):
        result = komsu.hash_response(f'{live_server}/a')
        assert result is not None
        assert set(result['levels'].keys()) == {'1', '2', '3'}

    def test_identical_bodies_group_on_real_server(self, live_server, capsys):
        tree, failed = komsu.process_urls_to_tree(
            [f'{live_server}/a', f'{live_server}/b', f'{live_server}/c'])
        assert failed == []
        assert len(tree) == 2  # /a + /b share a body, /c differs

    def test_same_body_different_status_on_real_server(self, live_server, capsys):
        tree, _ = komsu.process_urls_to_tree(
            [f'{live_server}/a', f'{live_server}/status/418'])
        assert len(tree) == 1
        l1 = next(iter(tree.values()))
        assert len(l1['children']) == 2  # same L1, divergent L2

    def test_redirect_is_not_followed(self, live_server):
        # /redirect returns 302 to /a; if redirects were followed its body
        # would be 'hello world' instead of the empty 302 body.
        redirect = komsu.hash_response(f'{live_server}/redirect')
        direct = komsu.hash_response(f'{live_server}/a')
        assert redirect['levels']['1'] != direct['levels']['1']

    def test_unreachable_host_fails_gracefully(self, capsys):
        # Port 9 (discard) is almost certainly closed locally.
        assert komsu.hash_response('http://127.0.0.1:9/x', timeout=1) is None

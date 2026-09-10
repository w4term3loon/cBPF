#!/usr/bin/env python3
"""Compile the repository's Markdown and local attachments into build/docs."""
from __future__ import annotations

import html
import argparse
import json
import posixpath
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'tools/docs'
GROUPS = ['Start here', 'Research', 'Results', 'Theory',
          'Implementation', 'Reproduction', 'Evidence', 'Private notes', 'Repository']
START = ['README.md', 'docs/overview.md', 'docs/README.md',
         'docs/research/claim-evidence.md', 'docs/presentation/README.md']
# Deep pages remain linked and searchable without competing with the reading route.
NAV_ENTRIES = set(START) | {
    'docs/research/related-work.md',
    'docs/research/capability-comparison.md', 'docs/research/trust-taxonomy.md',
    'docs/results/README.md', 'docs/results/earlier-findings.md',
    'theory/spatial.md', 'theory/ownership.md',
    'linux/spatial/README.md', 'linux/ownership/README.md',
    'docs/reproduction/README.md', 'evidence/README.md',
}
ALIASES = json.loads((ASSETS / 'redirects.json').read_text())
PRIVATE = 'docs/private/'
# This published source snapshot retains links from its original theory/ location.
# Keep the publication copy intact; direct code links to the retained source files and
# documentation links to the current pages, with an explicit reader notice.
SNAPSHOT = 'evidence/current/ownership-closure/source/kernel-ownership.md'
SNAPSHOT_LINKS = {
    'ownership.md': 'theory/ownership.md',
    '../evidence/current/ownership/README.md': 'evidence/current/ownership/README.md',
    '../evidence/current/ownership-closure/README.md': 'evidence/current/ownership-closure/README.md',
    **{f'../linux/ownership/{name}': f'{posixpath.dirname(SNAPSHOT)}/{name}'
       for name in ('cbpf_runtime.c', 'cbpf_jit.c', 'guest.c')},
    '../tools/run_ownership.sh': f'{posixpath.dirname(SNAPSHOT)}/run_ownership.sh',
}


def page_path(source: str) -> str:
    return 'index.html' if source == 'README.md' else str(Path(source).with_suffix('.html'))


def relative(target: str, page: str) -> str:
    return quote(posixpath.relpath(target, posixpath.dirname(page) or '.'))


def group(source: str) -> str:
    if source in START:
        return 'Start here'
    if source.startswith(PRIVATE):
        return 'Private notes'
    for prefix, label in [('docs/reproduction/', 'Reproduction'),
                          ('docs/results/', 'Results')]:
        if source.startswith(prefix):
            return label
    return {'docs': 'Research', 'theory': 'Theory', 'linux': 'Implementation',
            'evidence': 'Evidence'}.get(source.split('/')[0], 'Repository')


def text_of(token) -> str:
    return ''.join(c.content for c in token.children or []
                   if c.type in ('text', 'code_inline', 'softbreak'))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private', action='store_true',
                        help='Include local notes in a separate build/private-docs site')
    args = parser.parse_args()
    out = ROOT / 'build' / ('private-docs' if args.private else 'docs')
    # A delivered source selection has no Git history; use its explicit inventory.
    manifest = ROOT / 'SOURCE-MANIFEST.json'
    if manifest.is_file():
        names = [entry['path'] for entry in json.loads(manifest.read_text())['files']]
    else:
        # Git's file list excludes private/temporary ignored directories and .git.
        names = subprocess.check_output(
            ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT
        ).decode().split('\0')
    if args.private:
        private_root = ROOT / PRIVATE
        if not private_root.is_dir():
            raise SystemExit('Private documentation directory is not present.')
        names.extend(str(path.relative_to(ROOT)) for path in private_root.rglob('*')
                     if path.is_file())
    files = []
    for name in sorted(set(names)):
        if not name:
            continue
        name = posixpath.normpath(name)
        if Path(name).parts[0] in ('build', 'tmp', '.runtime') or '.git' in Path(name).parts:
            continue
        # Enforce this boundary even if an input manifest lists private notes.
        if name.startswith(PRIVATE) and not args.private:
            continue
        source = ROOT / name
        # Reject symlinked files and parents before copying any input.
        if source.resolve() != source or not source.resolve().is_relative_to(ROOT):
            raise ValueError(f'Source must be a regular repository path: {name}')
        if source.is_file():
            files.append(name)
    sources = [name for name in files if name.endswith('.md')]
    pages = {source: page_path(source) for source in sources}
    md = MarkdownIt('commonmark', {'html': False}).enable(['table', 'strikethrough'])
    md.renderer.rules['table_open'] = lambda *_: '<div class="table-scroll" tabindex="0"><table>\n'
    md.renderer.rules['table_close'] = lambda *_: '</table></div>\n'
    documents = []

    for source in sources:
        raw = (ROOT / source).read_text()
        tokens = md.parse(raw)
        references = set(re.findall(r'^\[(\d+)\]\s', raw, re.MULTILINE))
        headings, counts = [], Counter()
        for i, token in enumerate(tokens):
            if token.type == 'paragraph_open' and i + 1 < len(tokens):
                match = re.match(r'^\[(\d+)\]\s', tokens[i + 1].content)
                if match:
                    token.attrSet('id', 'reference-' + match[1])
            if token.type == 'heading_open':
                title = text_of(tokens[i + 1])
                slug = re.sub(r'[^\w\- ]', '', title.lower()).replace(' ', '-') or 'section'
                number = counts[slug]
                counts[slug] += 1
                anchor = slug + (f'-{number}' if number else '')
                token.attrSet('id', anchor)
                headings.append((int(token.tag[1:]), title, anchor))
            for child in token.children or []:
                if child.type != 'link_open':
                    continue
                parts = urlsplit(child.attrGet('href') or '')
                if parts.scheme or parts.netloc or not parts.path:
                    continue
                target = posixpath.normpath(posixpath.join(
                    posixpath.dirname(source), unquote(parts.path)))
                if source == SNAPSHOT and parts.path in SNAPSHOT_LINKS:
                    target = SNAPSHOT_LINKS[parts.path]
                target = ALIASES.get(target, target)
                if target in pages:
                    target = pages[target]
                if target in files or target in pages.values():
                    child.attrSet('href', urlunsplit(('', '', relative(target, pages[source]),
                                                     parts.query, parts.fragment)))
            # Numbered paper citations link to their own reference entries.
            # Work on text tokens only, preserving code and explicit hyperlinks.
            if references and token.children:
                children, in_link = [], False
                for child in token.children:
                    if child.type == 'link_open':
                        in_link = True
                    if child.type == 'text' and not in_link:
                        pieces = re.split(r'(\[\d+(?:,\s*\d+)*\])', child.content)
                        for piece in pieces:
                            numbers = re.findall(r'\d+', piece) if piece.startswith('[') else []
                            if numbers and all(number in references for number in numbers):
                                # A grouped citation keeps its original text and
                                # links to the first entry; every entry has an anchor.
                                opening = Token('link_open', 'a', 1)
                                opening.attrSet('href', '#reference-' + numbers[0])
                                children.append(opening)
                                text_token = Token('text', '', 0)
                                text_token.content = piece
                                children.extend([text_token, Token('link_close', 'a', -1)])
                            else:
                                text_token = Token('text', '', 0)
                                text_token.content = piece
                                children.append(text_token)
                    else:
                        children.append(child)
                    if child.type == 'link_close':
                        in_link = False
                token.children = children
        documents.append({'source': source, 'page': pages[source], 'group': group(source),
                          'title': headings[0][1] if headings else Path(source).stem,
                          'headings': headings, 'body': md.renderer.render(tokens, md.options, {}),
                          'text': raw.lower()})

    if out.resolve() != out or not out.resolve().is_relative_to(ROOT):
        raise ValueError('Output must be a regular path inside the repository')
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    # Attachments retain their repository paths; generated pages never expose
    # the worktree itself, ignored builds, runtime dependencies, or Git metadata.
    for name in files:
        destination = out / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    for name in ('site.css', 'site.js'):
        shutil.copyfile(ASSETS / name, out / name)
    search = [{'path': d['source'], 'text': d['text']} for d in documents]
    (out / 'search.json').write_text(json.dumps(search, ensure_ascii=False))

    esc = html.escape
    for doc in documents:
        page = doc['page']
        nav = []
        for label in GROUPS:
            items = sorted((d for d in documents if d['group'] == label),
                           key=lambda d: (START.index(d['source']) if d['source'] in START else 99,
                                          d['title'].lower(), d['source']))
            if not items:
                continue
            opened = label in ('Start here', 'Private notes', doc['group'])
            visible = {d['source'] for d in items
                       if d['source'] in NAV_ENTRIES or d['source'] == doc['source']
                       or d['source'].startswith(PRIVATE)}
            links = ''.join(
                f'<li data-path="{esc(d["source"])}"'
                + f' data-default="{str(d["source"] in visible).lower()}"'
                + ('' if d['source'] in visible else ' hidden')
                + f'><a href="{relative(d["page"], page)}"'
                + (' aria-current="page"' if d['source'] == doc['source'] else '')
                + f'>{esc(d["title"])}<small>{esc(d["source"])}</small></a></li>'
                for d in items)
            nav.append(f'<details data-open="{str(opened).lower()}"'
                       + (' open' if opened else '') + ('' if visible else ' hidden') + '>'
                       f'<summary>{label}</summary><ul>{links}</ul></details>')
        toc = ''.join(f'<li class="level-{level}"><a href="#{esc(anchor)}">{esc(title)}</a></li>'
                      for level, title, anchor in doc['headings'] if level in (2, 3))
        notice = (f'<p class="notice">Published evidence copy. '
                  f'<a href="{relative("evidence/README.html", page)}">Publication provenance</a> '
                  'distinguishes original experiment identities from redacted file identities. '
                  'Each record retains its recorded experimental scope.</p>'
                  if doc['group'] == 'Evidence' else '')
        if doc['source'] == SNAPSHOT:
            notice += ('<p class="notice">Published source snapshot. Code links use this snapshot; '
                       'documentation links point to the current repository.</p>')
        output = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(doc['title'])} · cBPF</title><link rel="stylesheet" href="{relative('site.css', page)}">
<script defer src="{relative('site.js', page)}" data-index="{relative('search.json', page)}"></script></head>
<body><a class="skip" href="#content">Skip to content</a>
<aside class="sidebar"><a class="brand" href="{relative('index.html', page)}">cBPF <span>Documentation</span></a>
<details id="navigation" open><summary>Browse documentation</summary>
<label for="search">Search all pages</label><input id="search" type="search" placeholder="Title or content" autocomplete="off">
<p id="search-status" role="status"></p><nav aria-label="Documentation">{''.join(nav)}</nav></details></aside>
<main id="content"><header><span>{esc(doc['source'])}</span>
<a href="{relative(doc['source'], page)}">Markdown source</a></header>{notice}<article>{doc['body']}</article></main>
<aside class="toc" aria-label="On this page"><strong>On this page</strong><ul>{toc}</ul></aside>
</body></html>'''
        (out / page).write_text(output)
    for old, new in ALIASES.items():
        if not old.endswith('.md') or old in pages or new not in pages:
            continue
        old_page = page_path(old)
        target = relative(pages[new], old_page)
        destination = out / old_page
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            f'<script>location.replace({json.dumps(target)} + location.search + location.hash);</script>'
            f'<noscript><meta http-equiv="refresh" content="0;url={esc(target, quote=True)}"></noscript>'
            f'<title>Page moved · cBPF</title><p>This page moved to '
            f'<a href="{esc(target, quote=True)}">{esc(new)}</a>.</p></html>')
    print(f'Built {len(documents)} Markdown pages with local attachments in {out}')


if __name__ == '__main__':
    main()

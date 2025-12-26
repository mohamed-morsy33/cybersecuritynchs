#!/usr/bin/env python3
"""
This script creates a JavaScript file IN THE SITE DIRECTORY that will be copied
"""
import json
import re
from pathlib import Path
import shutil

def clean_html(html):
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL|re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL|re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', html)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

print("Step 1: Building site...")
import subprocess
subprocess.run(['mkdocs', 'build'], check=True)

print("\nStep 2: Extracting content from built pages...")
site_dir = Path('site')
html_files = list(site_dir.glob('**/*.html'))
print(f"Found {len(html_files)} HTML files")

docs = []
for html_file in html_files:
    if '404' in str(html_file):
        continue
    
    try:
        content = html_file.read_text(encoding='utf-8')
        
        title_match = re.search(r'<title>(.*?)</title>', content)
        title = title_match.group(1).split(' - ')[0].strip() if title_match else html_file.stem
        
        rel_path = html_file.relative_to(site_dir)
        
        if str(rel_path) == 'index.html':
            location = '/'
        elif str(rel_path).endswith('/index.html'):
            location = '/' + str(rel_path)[:-11].replace('\\', '/')  # Remove /index.html (11 chars)
        else:
            location = '/' + str(rel_path)[:-5].replace('\\', '/') + '/'  # Remove .html, add /
        
        text = ''
        container_match = re.search(r'<div class="container"[^>]*>(.*?)</div>\s*<footer', content, re.DOTALL)
        if container_match:
            text = clean_html(container_match.group(1))
        
        if text and len(text) > 50:
            docs.append({
                'location': location,
                'title': title,
                'text': text[:2000]
            })
            print(f"  ✓ {title} -> {location}")
    except Exception as e:
        print(f"  ✗ {html_file.name}: {e}")

print(f"\nStep 3: Creating search JavaScript file...")

js_content = f"""// Auto-generated search index - DO NOT EDIT
window.searchIndex = {json.dumps({'config': {'lang': ['en'], 'separator': r'[\s\-]+'}, 'docs': docs}, indent=2, ensure_ascii=False)};
console.log('✓ Search index loaded:', window.searchIndex.docs.length, 'documents');
"""

custom_theme_dir = Path('custom_theme')
if not custom_theme_dir.exists():
    print("ERROR: custom_theme directory not found!")
    exit(1)

js_file = custom_theme_dir / 'search_index.js'
with open(js_file, 'w', encoding='utf-8') as f:
    f.write(js_content)

print(f"✓ Created: {js_file}")
print(f"✓ Size: {js_file.stat().st_size} bytes")
print(f"✓ Documents: {len(docs)}")

print("\nStep 4: Rebuilding with search data...")
subprocess.run(['mkdocs', 'build'], check=True)

print("\n" + "="*60)
print("SUCCESS! Search index embedded in theme.")
print("="*60)
print("\nNow run: mkdocs serve")
print("And search will work with full content!")

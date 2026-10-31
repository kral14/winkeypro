import re

html = open('apps/desktop_tauri/ui/index.html', encoding='utf-8').read()
ids = re.findall(r"getElementById\(['\"](.*?)['\"]\)", html)
print(f"Tapılan getElementById sayı: {len(ids)}")
unique_ids = sorted(list(set(ids)))
missing = []
for i in unique_ids:
    if f'id="{i}"' not in html and f"id='{i}'" not in html:
        missing.append(i)

print("Missing IDs:", missing)

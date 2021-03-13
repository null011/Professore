# Install

```bash
pip install .
```

### Upgrade

```bash
pip install -U .
```

# Usage

```bash
usage: professor.py [-h] -u URL [-c] [-d DOWNLOAD]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Url
  -c, --code            Print tags innter text
  -d DOWNLOAD, --download DOWNLOAD
                        Download remote libs, must be a path
```

Scan

```bash
professore --url https://github.com
```

Show `<link>` and `<script>` tags html

```bash
professore --url https://github.com --code
```

Download remote links

> File url link is used as filename, replacing `/` with `#`

```bash
professore --url https://github.com --download /tmp/github
```

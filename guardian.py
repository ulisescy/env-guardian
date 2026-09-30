import re
import sys
import os

SECRET_PATTERNS = [
    (r'(?i)api[_-]?key\s*[:=]\s*['"][0-9a-zA-Z_-]{16,}['"]', "Generic API Key"),
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI / DeepSeek Secret Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'(?i)private[_-]?key', "Private Key Reference"),
]

def scan_file(path: str) -> list[str]:
    findings = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                for pattern, name in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        findings.append(f"{path}:{i} - Potential {name}")
    except Exception:
        pass
    return findings

if __name__ == '__main__':
    print("Env Guardian security scanner loaded.")

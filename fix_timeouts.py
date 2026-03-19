#!/usr/bin/env python3
"""Add missing timeout= parameter to subprocess calls in agent.py files."""

import glob
import re


def add_timeout_to_subprocess_calls(filepath):
    """Add timeout=120 to subprocess.run/check_output/check_call calls missing it."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    original = content
    fixes = 0

    funcs = ["subprocess.run", "subprocess.check_output", "subprocess.check_call"]

    for func in funcs:
        start = 0
        while True:
            idx = content.find(func + "(", start)
            if idx == -1:
                break

            # Check if this line is a comment
            line_start = content.rfind("\n", 0, idx) + 1
            line_prefix = content[line_start:idx].lstrip()
            if line_prefix.startswith("#"):
                start = idx + 1
                continue

            # Find matching closing paren with basic string tracking
            paren_depth = 0
            pos = idx + len(func)
            found_close = -1
            in_str = None
            escape_next = False

            while pos < len(content):
                ch = content[pos]

                if escape_next:
                    escape_next = False
                    pos += 1
                    continue

                if ch == "\\":
                    escape_next = True
                    pos += 1
                    continue

                if in_str is None:
                    if ch == '"' and content[pos:pos+3] == '"""':
                        in_str = '"""'
                        pos += 3
                        continue
                    elif ch == "'" and content[pos:pos+3] == "'''":
                        in_str = "'''"
                        pos += 3
                        continue
                    elif ch == '"':
                        in_str = '"'
                    elif ch == "'":
                        in_str = "'"
                    elif ch == "(":
                        paren_depth += 1
                    elif ch == ")":
                        if paren_depth == 1:
                            found_close = pos
                            break
                        paren_depth -= 1
                else:
                    if in_str == '"""' and content[pos:pos+3] == '"""':
                        in_str = None
                        pos += 3
                        continue
                    elif in_str == "'''" and content[pos:pos+3] == "'''":
                        in_str = None
                        pos += 3
                        continue
                    elif in_str == '"' and ch == '"':
                        in_str = None
                    elif in_str == "'" and ch == "'":
                        in_str = None

                pos += 1

            if found_close == -1:
                start = idx + 1
                continue

            call_content = content[idx:found_close + 1]

            if "timeout" not in call_content:
                # Insert timeout=120 before the closing paren
                before_close = content[:found_close].rstrip()
                after_close = content[found_close + 1:]

                # Determine indentation by looking at the line with the func call
                func_line_start = content.rfind("\n", 0, idx) + 1
                indent = ""
                for c in content[func_line_start:]:
                    if c in (" ", "\t"):
                        indent += c
                    else:
                        break

                # Check if call is multiline
                call_text = content[idx:found_close]
                if "\n" in call_text:
                    # Multiline: add timeout on new line with proper indent
                    content = before_close + ", timeout=120\n" + indent + ")" + after_close
                else:
                    # Single line: add inline
                    content = content[:found_close] + ", timeout=120)" + after_close

                fixes += 1

            start = idx + 1

    if fixes > 0:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    return fixes


if __name__ == "__main__":
    files = sorted(glob.glob("skills/*/scripts/agent.py"))
    total_fixed = 0
    files_fixed = 0

    for filepath in files:
        n = add_timeout_to_subprocess_calls(filepath)
        if n > 0:
            total_fixed += n
            files_fixed += 1
            print(f"  Fixed {n} calls in {filepath}")

    print(f"\nTotal: {total_fixed} subprocess calls fixed across {files_fixed} files")

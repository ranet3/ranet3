# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: FSL-1.1-ALv2

# absent.py CHECKS PKGS: a grep of ranet3's journal that a check expects to
# fail passes on nothing once the Go text it copies is renamed. So every call
# under CHECKS that expects a command to fail, .fail( or wait_until_fails( on
# any machine, must hand it a command absent.py can read: string literals, a
# name its file binds to one or to a journal, or a call of a function of its
# file that returns one. A command that reads the journal, of ranet3's unit in
# any spelling of journalctl, of no unit, or of a unit it cannot name, must be
# the journal piped into stages of grep -F with quoted fixed strings, each held
# in a string literal of a non-test Go file under PKGS. A call it cannot read
# that way fails the check, since its strings would go unchecked, and so does
# finding no such call at all.
import os
import re
import sys

NEGATIVE = re.compile(r"\.(?:fail|wait_until_fails)\(")
# a string literal of Python, and the leading ones of a call's argument, which Python joins into one command
STRING = r""""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'"""
LITERAL = re.compile(r"\s*f?(" + STRING + ")")
# what a file binds a name to: a string literal, a journal after a cursor, or the one return of a function
BINDS = [
    (re.compile(r"^[ \t]*(\w+) = f?(" + STRING + r")[ \t]*$", re.M), lambda m: m.group(2)[1:-1]),
    (re.compile(r"""^[ \t]*(\w+) = journal_after\(\w+, "([^"]+)"\)""", re.M), lambda m: "journalctl -u " + m.group(2)),
    (re.compile(r"^[ \t]*def (\w+)\([^)]*\):[ \t]*\n[ \t]*return f?(" + STRING + r")[ \t]*$", re.M), lambda m: m.group(2)[1:-1]),
]
# the unit a journalctl reads, in each spelling of its flag
UNIT = re.compile(r"(?:(?<![\w-])-u ?|--unit[= ]|_SYSTEMD_UNIT=)['\"]?([^\s'\"|]+)")
# one stage after the journal: grep with its flags, then one quoted string or an -e before each
STAGE = re.compile(r"grep -([a-zA-Z]+)((?: -e '[^'{}]+')+| '[^'{}]+')")
# a token of Go: a comment, an interpreted or a raw string literal, or a rune literal
GO = re.compile(r"""//[^\n]*|/\*.*?\*/|"(?:[^"\\\n]|\\.)*"|`[^`]*`|'(?:[^'\\\n]|\\.)*'""", re.S)


def argument(text, start):
    """the text of the call whose argument starts at start, up to its closing parenthesis, outside Python's string literals"""
    depth, quote, i = 1, None, start
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def commands(arg, bound):
    """the commands a call's first argument can be: its string literals joined, or what the name or the function it
    starts with is bound to, or None where it is any other expression"""
    parts, at = [], 0
    while m := LITERAL.match(arg, at):
        parts.append(m.group(1)[1:-1])
        at = m.end()
    rest = arg[at:].strip()
    if parts:
        return ["".join(parts)] if rest == "" or rest.startswith(",") else None
    m = re.match(r"(\w+)\s*(?:\([^()]*\))?\s*(?:,|$)", rest)
    return bound.get(m.group(1)) if m else None


def reads(cmd, kinds):
    """whether cmd reads a journal that may hold ranet3's lines: "yes", "no", or "unknown" where it starts from a name
    absent.py cannot resolve"""
    stages = cmd.split(" | ")
    source = stages[0].strip()
    if source.startswith(("{", "${")):
        named = re.fullmatch(r"\{(\w+)\}", source)
        return kinds.get(named.group(1), "unknown") if named else "unknown"
    if any(kinds.get(name) == "yes" for name in re.findall(r"\{(\w+)\}", cmd)):
        return "yes"
    journals = [stage for stage in stages if re.search(r"\bjournalctl\b", stage)]
    units = [unit for stage in journals for unit in UNIT.findall(stage)]
    if not journals or units and not any(u.startswith("ranet3") or "{" in u for u in units):
        return "no"
    return "yes"


def greps(cmd, kinds):
    """the fixed strings of a command that pipes the journal into grep -F stages, or None for any other form"""
    stages = cmd.split(" | ")
    source = stages[0].strip()
    named = re.fullmatch(r"\{(\w+)\}", source)
    if not (named and kinds.get(named.group(1)) == "yes" or re.match(r"journalctl\b[^{}]*$", source)) or len(stages) < 2:
        return None
    strings = []
    for stage in stages[1:]:
        m = STAGE.fullmatch(stage.strip())
        if not m or "F" not in m.group(1) or set(m.group(1)) & set("EGPv"):
            return None
        strings += re.findall(r"'([^']+)'", m.group(2))
    return strings


def go_strings(text):
    """the contents of the string literals of a Go file, escapes read, its comments and rune literals left out"""
    out = []
    for m in GO.finditer(text):
        token = m.group(0)
        if token[0] == '"':
            out.append(re.sub(r"\\(.)", lambda e: {"n": "\n", "t": "\t"}.get(e.group(1), e.group(1)), token[1:-1]))
        elif token[0] == "`":
            out.append(token[1:-1])
    return out


def main():
    checks, pkgs = sys.argv[1:3]
    absent, unread, unresolved = {}, [], []
    for root, _, files in os.walk(checks):
        for name in sorted(files):
            if not name.endswith(".nix"):
                continue
            path = os.path.join(root, name)
            text = open(path).read()
            bound = {}
            for pattern, value in BINDS:
                for m in pattern.finditer(text):
                    bound.setdefault(m.group(1), []).append(value(m))
            # a name reads the journal where any command it is bound to does, and is unknown where one of them is
            kinds = {}
            for _ in range(len(bound) + 1):
                kinds = {n: next((k for k in ["yes", "unknown"] if k in {reads(c, kinds) for c in cmds}), "no") for n, cmds in bound.items()}
            for call in NEGATIVE.finditer(text):
                arg = argument(text, call.end())
                where = f"{path}:{text.count(chr(10), 0, call.start()) + 1}"
                cmds = commands(arg, bound) if arg is not None else None
                if cmds is None or any(reads(c, kinds) == "unknown" for c in cmds):
                    unresolved.append(where)
                    continue
                for cmd in cmds:
                    if reads(cmd, kinds) == "no":
                        continue
                    strings = greps(cmd, kinds)
                    if strings is None:
                        unread.append(where)
                        continue
                    for s in strings:
                        absent.setdefault(s, where)
    for where in unresolved:
        print(f"{where} expects a command to fail that is no string literal, bound name or function of its file absent.py can read, so whether it reads ranet3's journal cannot be checked", file=sys.stderr)
    for where in unread:
        print(f"{where} expects a read of ranet3's journal to fail that is not the journal piped into grep -F stages of quoted fixed strings, so its strings cannot be checked", file=sys.stderr)
    failed = bool(unresolved or unread)
    if not absent and not failed:
        print("absent.py found no grep under checks that a check expects to fail on ranet3's journal", file=sys.stderr)
        failed = True
    held = set()
    for root, _, files in os.walk(pkgs):
        for name in files:
            if name.endswith(".go") and not name.endswith("_test.go"):
                literals = go_strings(open(os.path.join(root, name), errors="replace").read())
                held.update(s for s in absent if any(s in literal for literal in literals))
    for s, where in sorted(absent.items()):
        if s not in held:
            print(f"{where} expects a grep of ranet3's journal for '{s}' to fail, and no string literal of non-test Go under pkgs holds it", file=sys.stderr)
            failed = True
    print(f"absent.py: {len(absent)} strings of the greps checks expect to fail on ranet3's journal, {len(held)} held")
    sys.exit(1 if failed else 0)


main()

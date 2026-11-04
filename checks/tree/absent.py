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
# in a string literal of a non-test Go file under PKGS. A count of the journal
# that .succeed( or wait_until_succeeds( reads, a grep with -c in any flag or
# --count or a pipe into wc -l, must be that form too, a trailing || true
# allowed, and fails where absent.py cannot read it. absent.py reads each
# command as the shell gets it, its string literals unescaped as Python reads
# them. The count must sit in the string literals of the call's own text, as
# one built into a name the file does not bind to a string literal is not
# seen. A call it cannot read that way fails the check, since
# its strings would go unchecked, and so does finding no such call at all.
import ast
import os
import re
import sys

# a call that expects its commands to fail, or that must succeed and is read where it counts
CALLS = re.compile(r"\.(fail|wait_until_fails|succeed|wait_until_succeeds)\(")
# a count of lines in a command as the shell gets it: a grep with -c in any of its flags or --count anywhere in its
# stage, a single-quoted run, a double-quoted run with its escapes and a backslash escape each read whole so a pipe or
# a quote inside one ends no stage, and a flag ending at a quote as at a space, or a pipe into wc -l
COUNTS = re.compile(r"""\bgrep\b(?:[^|'"\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")*\s(?:-[a-zA-Z]*c[a-zA-Z]*|--count)(?![^\s'"])|\|\s*wc\s+-l\b""")
# a string literal of Python, and the leading ones of a call's argument, which Python joins into one command
STRING = r""""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'"""
LITERAL = re.compile(r"\s*f?(" + STRING + ")")
# what a file binds a name to: a string literal, a journal after a cursor, or the one return of a function
BINDS = [
    (re.compile(r"^[ \t]*(\w+) = f?(" + STRING + r")[ \t]*$", re.M), lambda m: ast.literal_eval(m.group(2))),
    (re.compile(r"""^[ \t]*(\w+) = journal_after\(\w+, "([^"]+)"\)""", re.M), lambda m: "journalctl -u " + m.group(2)),
    (re.compile(r"^[ \t]*def (\w+)\([^)]*\):[ \t]*\n[ \t]*return f?(" + STRING + r")[ \t]*$", re.M), lambda m: ast.literal_eval(m.group(2))),
]
# the unit a journalctl reads, in each spelling of its flag
UNIT = re.compile(r"(?:(?<![\w-])-u ?|--unit[= ]|_SYSTEMD_UNIT=)['\"]?([^\s'\"|]+)")
# one stage after the journal: grep with its flags, then one quoted string or an -e before each
STAGE = re.compile(r"grep -([a-zA-Z]+)((?: -e '[^'{}]+')+| '[^'{}]+')")
# a token of Go: a comment, an interpreted or a raw string literal, or a rune literal
GO = re.compile(r"""//[^\n]*|/\*.*?\*/|"(?:[^"\\\n]|\\.)*"|`[^`]*`|'(?:[^'\\\n]|\\.)*'""", re.S)


def arguments(text, start):
    """the arguments of the call whose text starts at start, cut at its commas up to its closing parenthesis, outside
    brackets and Python's string literals, or None where the call has no closing parenthesis"""
    pieces, depth, quote, at, i = [], 0, None, start, start
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return pieces + [text[at:i]]
            depth -= 1
        elif c == "," and depth == 0:
            pieces.append(text[at:i])
            at = i + 1
        i += 1
    return None


def literals(piece):
    """the one command an argument of string literals alone is, which Python joins, or None for any other expression"""
    parts, at = [], 0
    while m := LITERAL.match(piece, at):
        parts.append(ast.literal_eval(m.group(1)))
        at = m.end()
    return "".join(parts) if parts and piece[at:].strip() == "" else None


def constants(piece):
    """the string constants of an argument that is any other expression, in their order and unescaped as Python reads
    them, joined, or the argument's own text where Python cannot parse it"""
    try:
        tree = ast.parse(piece.strip(), mode="eval")
    except SyntaxError:
        return piece
    nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return "".join(n.value for n in sorted(nodes, key=lambda n: (n.lineno, n.col_offset)))


def commands(pieces, bound):
    """the commands a call's arguments can be: each argument of string literals, and what the name or the function the
    first starts with is bound to, or None where the first is any other expression"""
    out = []
    for i, piece in enumerate(pieces):
        if (cmd := literals(piece)) is not None:
            out.append(cmd)
        elif i == 0:
            m = re.fullmatch(r"\s*(\w+)\s*(?:\([^()]*\))?\s*", piece)
            if not m or m.group(1) not in bound:
                return None
            out += bound[m.group(1)]
    return out


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
            for call in CALLS.finditer(text):
                counted = call.group(1) in ("succeed", "wait_until_succeeds")
                pieces = arguments(text, call.end())
                where = f"{path}:{text.count(chr(10), 0, call.start()) + 1}"
                cmds = commands(pieces, bound) if pieces is not None else None
                if counted:
                    # a command that must succeed matters only where it counts lines
                    if cmds is None and pieces is not None and not any(COUNTS.search(constants(p)) for p in pieces):
                        continue
                    if cmds is not None:
                        cmds = [c.removesuffix(" || true") for c in cmds if COUNTS.search(c)]
                what = "counts lines through a command that must succeed" if counted else "expects a command to fail"
                if cmds is None or any(reads(c, kinds) == "unknown" for c in cmds):
                    unresolved.append((where, what))
                    continue
                for cmd in cmds:
                    if reads(cmd, kinds) == "no":
                        continue
                    strings = greps(cmd, kinds)
                    if strings is None:
                        unread.append((where, what))
                        continue
                    for s in strings:
                        absent.setdefault(s, where)
    for where, what in unresolved:
        print(f"{where} {what} that is no string literal, bound name or function of its file absent.py can read, so whether it reads ranet3's journal cannot be checked", file=sys.stderr)
    for where, what in unread:
        print(f"{where} {what} on ranet3's journal that is not the journal piped into grep -F stages of quoted fixed strings, so its strings cannot be checked", file=sys.stderr)
    failed = bool(unresolved or unread)
    if not absent and not failed:
        print("absent.py found no grep of ranet3's journal under checks that a check expects to fail or counts", file=sys.stderr)
        failed = True
    held = set()
    for root, _, files in os.walk(pkgs):
        for name in files:
            if name.endswith(".go") and not name.endswith("_test.go"):
                literals = go_strings(open(os.path.join(root, name), errors="replace").read())
                held.update(s for s in absent if any(s in literal for literal in literals))
    for s, where in sorted(absent.items()):
        if s not in held:
            print(f"{where} greps ranet3's journal for '{s}', which a rename leaves matching nothing, and no string literal of non-test Go under pkgs holds it", file=sys.stderr)
            failed = True
    print(f"absent.py: {len(absent)} strings of the greps checks expect to fail or count on ranet3's journal, {len(held)} held")
    sys.exit(1 if failed else 0)


main()

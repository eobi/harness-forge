"""What counts as a dangerous destination on the JVM.

`analysis/sinks.py` weights `strcpy`, `memcpy`, `alloca`, `gets`. **None of them exist here**,
and porting that table would produce a reachability gate that always scores zero — a gate
reporting "0% of sinks reached" for a library with no sinks to reach, which reads as a weak
harness rather than an inapplicable measure.

The Java table answers the same question about a different kind of danger. C sinks are places
memory is corrupted; JVM sinks are places a **trust boundary is crossed**. Nothing is
overwritten when `ObjectInputStream.readObject` deserialises attacker bytes — and that is the
single most damaging bug class the JVM has. A memory-shaped engine scores it zero.

Weights are relative within this table only, and are ordered by what a maintainer would treat
as urgent, not by how often the pattern appears.
"""
from __future__ import annotations

import re

SINKS: dict = {
    # Remote code execution, directly.
    "deserialize":  (re.compile(r"\b(?:ObjectInputStream|readObject|readUnshared|"
                                r"XMLDecoder|readResolve)\b"), 6.0),
    "exec":         (re.compile(r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|"
                                r"ProcessBuilder|ProcessImpl)\b"), 6.0),
    "script":       (re.compile(r"\b(?:ScriptEngine|GroovyShell|Nashorn|"
                                r"ExpressionParser|SpelExpressionParser|"
                                r"MVEL|OgnlContext)\b"), 6.0),
    "reflect":      (re.compile(r"\b(?:Class\s*\.\s*forName|ClassLoader\s*\.\s*loadClass|"
                                r"defineClass|MethodHandles\s*\.\s*lookup|"
                                r"setAccessible)\b"), 5.0),
    # Injection into another interpreter.
    "sql":          (re.compile(r"\b(?:Statement\s*\.\s*execute|executeQuery|executeUpdate|"
                                r"createStatement|createQuery|nativeQuery)\b"), 4.5),
    "ldap":         (re.compile(r"\b(?:InitialDirContext|DirContext\s*\.\s*search|"
                                r"InitialContext\s*\.\s*lookup)\b"), 4.5),
    "xpath":        (re.compile(r"\b(?:XPath\s*\.\s*compile|XPathExpression)\b"), 3.5),
    # XXE and friends: a parser configured without secure processing.
    "xml":          (re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLReader|"
                                r"XMLInputFactory|SAXBuilder|Unmarshaller)\b"), 4.0),
    # Server-side request forgery and path traversal: attacker chooses the destination.
    "url":          (re.compile(r"\b(?:new\s+URL|URI\s*\.\s*create|HttpClient|"
                                r"openConnection|openStream)\b"), 3.5),
    "path":         (re.compile(r"\b(?:new\s+File|Paths\s*\.\s*get|Path\s*\.\s*of|"
                                r"FileInputStream|FileOutputStream|RandomAccessFile)\b"), 3.5),
    # Denial of service: the JVM's characteristic failure, and the one that needs a RATIO
    # rather than a threshold — see java/exceptions.with_amplification.
    "regex":        (re.compile(r"\b(?:Pattern\s*\.\s*(?:compile|matches)|"
                                r"String\s*\.\s*(?:matches|split|replaceAll))\b"), 3.0),
    "alloc":        (re.compile(r"\bnew\s+(?:byte|char|int|long|Object)\s*\[[^\]]*"
                                r"[a-zA-Z_]\w*[^\]]*\]"), 2.5),
    "inflate":      (re.compile(r"\b(?:Inflater|GZIPInputStream|ZipInputStream|"
                                r"ZipFile|JarFile)\b"), 2.5),
    # The bounds and cast checks: not sinks in the C sense, but the places the JVM's
    # always-on oracle fires, which is what a Java finding usually IS.
    "index":        (re.compile(r"\w+\s*\[\s*[a-zA-Z_]\w*\s*\]"), 1.5),
    "cast":         (re.compile(r"\(\s*[A-Z]\w*\s*\)\s*[a-zA-Z_]\w*"), 1.0),
    "arraycopy":    (re.compile(r"\bSystem\s*\.\s*arraycopy\b"), 1.5),
}

# Configuration that DISARMS a sink. A DocumentBuilderFactory with secure processing on is
# not an XXE risk, and scoring it as one sends a maintainer to a line that is already safe.
DISARMED = {
    "xml": re.compile(r"FEATURE_SECURE_PROCESSING|disallow-doctype-decl|"
                      r"setExpandEntityReferences\s*\(\s*false"),
}


def scan(text: str) -> dict:
    """{kind: count} for one compilation unit's source."""
    out: dict = {}
    for kind, (pat, _w) in SINKS.items():
        n = len(pat.findall(text or ""))
        if n:
            out[kind] = n
    for kind, pat in DISARMED.items():
        if kind in out and pat.search(text or ""):
            out.pop(kind)
    return out


def weight(kinds) -> float:
    return sum(SINKS[k][1] for k in kinds if k in SINKS)

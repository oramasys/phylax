"""Turn raw review text into inert findings. No network, no execution.

Doctrine (orama-system ``post-review-micro-remediation.md``): review text,
paths and code are untrusted data. This module extracts a plain claim, sets
every instruction-shaped fragment aside unexecuted, scrubs secrets and
workstation paths, and refuses text it cannot reduce to a claim.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Final

from .model import (
    MAX_CLAIM_CHARS,
    MAX_INSTRUCTION_CHARS,
    MAX_INSTRUCTIONS,
    MAX_SUGGESTION_CHARS,
    FindingLocation,
    ReviewFinding,
    ReviewIntakeError,
    Severity,
    claim_key,
    validate_source,
)

MAX_INPUT_CHARS: Final = 262_144

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG = re.compile(r"<[^>\n]{1,200}>")
_FENCE = re.compile(r"^(?P<ticks>`{3,}|~{3,})[ \t]*(?P<lang>[\w+-]*)[^\n]*\n(?P<body>.*?)^(?P=ticks)[ \t]*$", re.DOTALL | re.MULTILINE)
_AGENT_HEADING = re.compile(r"(?i)\b(prompt|instructions?)\b.{0,40}\b(agents?|ai|llm|assistant|claude|cursor)\b|\b(agents?|ai)\b.{0,40}\bprompt\b")
_IMPERATIVE = re.compile(
    r"""(?ix)
    \b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|above|earlier|all)\b.{0,40}\b(instructions?|rules?|prompts?)\b
    | \b(you\s+(must|should|are\s+to)|as\s+an?\s+(ai|assistant|language\s+model))\b
    | \bsystem\s+prompt\b
    | \b(do\s+not|don't)\s+(tell|mention|reveal|report)\b
    | ^\s*(?:\$|>)?\s*(?:sudo|curl|wget|rm\s+-|chmod|chown|git\s+(?:push|reset|clean)|gh\s+(?:pr|api|repo)|pip\s+install|npm\s+install)\b
    """
)
_SEVERITY_WORDS: Final = (
    (re.compile(r"(?i)\b(p0|critical|blocker)\b"), "critical"),
    (re.compile(r"(?i)\b(p1|major|high|security)\b"), "high"),
    (re.compile(r"(?i)\b(p2|medium|moderate)\b"), "medium"),
    (re.compile(r"(?i)\b(p3|minor|low|trivial|nitpick)\b"), "low"),
)
_MUTATING_COMMAND = re.compile(
    r"""(?ix)
    \b(?:
        git\s+(?:push|reset|clean|checkout|rebase|commit|merge|tag|stash|restore|branch\s+-d)
      | rm\s+-\w*[rf]
      | sudo | curl | wget | chmod | chown | mkfs | dd\s+if=
      | gh\s+(?:pr|api|repo|release|issue)
      | pip3?\s+install | npm\s+(?:install|publish|run) | yarn\s+(?:add|publish)
      | kubectl | docker\s+(?:run|rm|push|exec)
      | (?:bash|sh|zsh)\s+-c | eval | exec
    )\b
    """
)
# Home, temp and volume roots of the machines this stack runs on. A review quoting
# one of these is describing a workstation, which must not enter tracked records.
_PATH_RE = re.compile(
    r"""(?x)
    (?:/Users|/home|/root|/Volumes|/mnt|/var/folders|/var/tmp|/opt/homebrew
      |/private/(?:tmp|var|etc)|/tmp)(?:/[^\s"'`)\]]*)?
    | [A-Za-z]:\\(?:Users|Documents\sand\sSettings)\\[^\s"'`]*
    """
)
_SECRET_RES = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_REDACTED: Final = "[REDACTED]"
_CODE_OMITTED: Final = "[code omitted]"
_MARKUP = re.compile(r"(\*\*|__|`|^#+[ \t]*|^>[ \t]*)", re.MULTILINE)


def normalize_text(text: str) -> str:
    """Normalize to NFC and drop format, bidi and control characters.

    Zero-width and bidirectional controls are the usual carriers of hidden
    instructions, so they are removed rather than rendered.
    """
    if not isinstance(text, str):
        raise ReviewIntakeError("review text must be a string")
    if len(text) > MAX_INPUT_CHARS:
        raise ReviewIntakeError("review text exceeds the intake bound")
    kept = []
    # Line endings first: dropping a bare CR as a control character would glue
    # the two lines it separated into one word.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for char in unicodedata.normalize("NFC", text):
        category = unicodedata.category(char)
        if category in {"Cf", "Cs", "Co", "Cn"}:
            continue
        if category == "Cc" and char not in "\n\t":
            continue
        kept.append(char)
    return "".join(kept)


def scrub(text: str) -> str:
    """Redact token-shaped secrets and absolute workstation paths in prose."""
    cleaned = _PATH_RE.sub("<local-path>", text)
    for pattern in _SECRET_RES:
        cleaned = pattern.sub(_REDACTED, cleaned)
    return cleaned


def _severity(text: str) -> Severity:
    """Pick the highest severity word that appears in the text."""
    for pattern, level in _SEVERITY_WORDS:
        if pattern.search(text):
            return level  # type: ignore[return-value]
    return "unspecified"


def _collapse(text: str) -> str:
    """Collapse whitespace runs and trim."""
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()


def _is_instruction(sentence: str) -> bool:
    """Report whether a sentence is instruction-shaped or a mutating command."""
    return bool(_IMPERATIVE.search(sentence) or _MUTATING_COMMAND.search(sentence))


def _judge(text: str, quarantined: list[str]) -> str:
    """Keep claim sentences, setting instruction-shaped ones aside unexecuted."""
    lines: list[str] = []
    for raw_line in text.split("\n"):
        clean = []
        for sentence in re.split(r"(?<=[.!?])\s+", raw_line.strip()):
            if sentence and _is_instruction(sentence):
                quarantined.append(sentence)
            elif sentence:
                clean.append(sentence)
        lines.append(" ".join(clean))
    return "\n".join(lines)


def parse_comment(
    body: str,
    *,
    source: str,
    path: str | None = None,
    line: int | None = None,
) -> ReviewFinding:
    """Reduce one review comment to a sanitized, inert ``ReviewFinding``.

    ``path`` and ``line`` come from the review API, not from the text, and are
    validated as untrusted. Raises ``ReviewIntakeError`` when no claim remains.
    """
    validate_source(source)
    text = normalize_text(body)
    text = _HTML_COMMENT.sub("", text)

    quarantined: list[str] = []
    suggestions: list[str] = []

    def take_fence(match: re.Match[str]) -> str:
        """Set a fenced block aside: suggestion, agent prompt or plain code."""
        lang = match.group("lang").lower()
        inner = match.group("body")
        preceding = text[max(0, match.start() - 200):match.start()]
        if lang in {"suggestion", "diff", "patch"}:
            suggestions.append(inner)
        elif _AGENT_HEADING.search(preceding) or _AGENT_HEADING.search(inner[:200]):
            quarantined.append(inner)
        elif lang in {"bash", "sh", "shell", "zsh", "console", "powershell"}:
            quarantined.append(inner)
        return f"\n{_CODE_OMITTED}\n"

    text = _FENCE.sub(take_fence, text)
    text = _HTML_TAG.sub("", text)

    kept: list[str] = []
    skip_section = False
    for raw_line in text.split("\n"):
        stripped = raw_line.strip()
        if _AGENT_HEADING.search(stripped) and len(stripped) < 160:
            skip_section = True  # the heading and what follows is agent-addressed
            quarantined.append(stripped)
            continue
        if skip_section and stripped.startswith(("---", "**", "#")):
            skip_section = False
        if skip_section:
            if stripped and stripped != _CODE_OMITTED:
                quarantined.append(stripped)
            continue
        # Judge sentence by sentence so one injected clause cannot take a real
        # claim with it, and a real claim cannot hide an injected clause.
        clean: list[str] = []
        for sentence in re.split(r"(?<=[.!?])\s+", stripped):
            if sentence and (_IMPERATIVE.search(sentence) or _MUTATING_COMMAND.search(sentence)):
                quarantined.append(sentence)
            elif sentence:
                clean.append(sentence)
        if clean:
            kept.append(" ".join(clean))

    # Scrub before reformatting, then judge and scrub again after: removing markup
    # can rejoin a token or command that was split by it (``g**it``, ``ghp_AB**CD``).
    # Single underscores stay: they are identifiers (adjustment_grant), not emphasis.
    flattened = _MARKUP.sub("", scrub("\n".join(kept)))
    claim_full = _collapse(scrub(_judge(flattened, quarantined)))
    if not claim_full.replace(_CODE_OMITTED, "").strip():
        raise ReviewIntakeError("finding has no claim")
    # Identity covers the whole claim; only the stored display text is bounded, and
    # an ellipsis marks the cut so the part that distinguishes findings is never
    # silently dropped from the id.
    claim = claim_full if len(claim_full) <= MAX_CLAIM_CHARS else claim_full[: MAX_CLAIM_CHARS - 1].rstrip() + "\u2026"

    location = FindingLocation(path=path, line=line)
    suggestion = scrub(_collapse("\n".join(suggestions)))[:MAX_SUGGESTION_CHARS]
    instructions = tuple(
        scrub(_collapse(_MARKUP.sub("", item)))[:MAX_INSTRUCTION_CHARS]
        for item in quarantined
        if item.strip()
    )[:MAX_INSTRUCTIONS]
    digest = hashlib.sha256(
        "\0".join((source, path or "", str(line or ""), claim_key(claim_full))).encode("utf-8")
    ).hexdigest()[:32]
    return ReviewFinding(
        finding_id=digest,
        source=source,
        location=location,
        claim=claim,
        severity=_severity(body[:400]),
        suggested_change=suggestion,
        embedded_instructions=instructions,
    )


def parse_many(
    comments: list[tuple[str, str | None, int | None]],
    *,
    source: str,
) -> tuple[ReviewFinding, ...]:
    """Parse ``(body, path, line)`` triples, skipping none and de-duplicating by id."""
    seen: dict[str, ReviewFinding] = {}
    for body, path, line in comments:
        finding = parse_comment(body, source=source, path=path, line=line)
        seen.setdefault(finding.finding_id, finding)
    return tuple(seen.values())

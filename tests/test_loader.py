import unittest

from agent_sec_scanner.loader import load_text, strip_jsonc


class LoaderTests(unittest.TestCase):
    def test_jsonc_keeps_urls_in_strings(self):
        txt = '{\n // comment\n "servers": {"a": {"url": "https://x.example/mcp", /* c */ "type": "http",},},\n}'
        doc = load_text(txt, ".vscode/mcp.json")
        self.assertEqual(doc.servers[0].url, "https://x.example/mcp")
        self.assertIn("https://x.example/mcp", strip_jsonc(txt))

    def test_formats(self):
        cases = {
            '{"mcpServers": {"a": {"command": "x"}}}': "mcpServers",
            '{"servers": {"a": {"type": "stdio", "command": "x"}}}': "servers",
            '{"mcp": {"servers": {"a": {"command": "x"}}}}': "mcp.servers",
            '{"context_servers": {"a": {"command": {"path": "x", "args": ["--y"]}}}}': "context_servers",
            '{"projects": {"/p": {"mcpServers": {"a": {"command": "x"}}}}}': "Claude Code",
        }
        for txt, label in cases.items():
            doc = load_text(txt)
            self.assertEqual(len(doc.servers), 1, txt)
            self.assertTrue(any(label in f for f in doc.formats), (txt, doc.formats))

    def test_codex_toml(self):
        doc = load_text('[mcp_servers.s]\ncommand = "uvx"\nargs = ["pkg==1.0"]\n', "config.toml")
        self.assertEqual(doc.servers[0].command, "uvx")
        self.assertEqual(doc.servers[0].args, ["pkg==1.0"])

    def test_yaml_list_form(self):
        doc = load_text("mcpServers:\n  - name: s1\n    command: npx\n    args: [\"-y\", \"a@1.0.0\"]\n", "config.yaml")
        self.assertEqual(doc.servers[0].name, "s1")

    def test_tools_manifest_jsonrpc(self):
        doc = load_text('{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"t","description":"d"}]}}')
        self.assertEqual(doc.tools[0].name, "t")

    def test_generic_servers_key_is_not_misread(self):
        doc = load_text('{"servers": {"prod": {"host": "db1", "port": 5432}}}')
        self.assertEqual(doc.servers, [])


if __name__ == "__main__":
    unittest.main()

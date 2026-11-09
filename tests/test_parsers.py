import unittest

from agent_guard import parsers


class Json5Tests(unittest.TestCase):
    def test_comments_trailing_commas_unquoted_keys(self):
        text = """
        // top comment
        { gateway: { port: 18789, bind: 'lan', /* inline */ auth: { mode: "token", }, },
          list: [1, 2, 3,], on: true, nothing: null }
        """
        data = parsers.load_json5(text)
        self.assertEqual(data["gateway"]["bind"], "lan")
        self.assertEqual(data["gateway"]["auth"]["mode"], "token")
        self.assertEqual(data["list"], [1, 2, 3])
        self.assertIs(data["on"], True)
        self.assertIsNone(data["nothing"])

    def test_invalid_raises(self):
        with self.assertRaises(parsers.ParseError):
            parsers.load_json5("{ a: ")


class YamlTests(unittest.TestCase):
    def test_nested_and_lists(self):
        text = """
approvals:
  mode: off   # risky
  cron_mode: "approve"
skills:
  external_dirs:
    - ~/shared-skills
    - /opt/skills
webapp:
  enabled: true
  port: 9120
flow: [a, b]
"""
        data = parsers.load_yaml_lite(text)
        self.assertEqual(data["approvals"]["mode"], "off")
        self.assertEqual(data["approvals"]["cron_mode"], "approve")
        self.assertEqual(data["skills"]["external_dirs"], ["~/shared-skills", "/opt/skills"])
        self.assertIs(data["webapp"]["enabled"], True)
        self.assertEqual(data["webapp"]["port"], 9120)
        self.assertEqual(data["flow"], ["a", "b"])

    def test_block_scalar_is_one_string(self):
        data = parsers.load_yaml_lite("prompt: |\n  line one\n  line two\nnext: 1\n")
        self.assertIn("line two", data["prompt"])
        self.assertEqual(data["next"], 1)


class DotenvTests(unittest.TestCase):
    def test_quotes_comments_export(self):
        env = parsers.load_dotenv('A=1\nexport B="two words"\n# c\nC=x # trailing\nD=\'q\'\n')
        self.assertEqual(env, {"A": "1", "B": "two words", "C": "x", "D": "q"})


class TruthyTests(unittest.TestCase):
    def test_values(self):
        self.assertTrue(parsers.truthy("True"))
        self.assertTrue(parsers.truthy("1"))
        self.assertFalse(parsers.truthy("no"))
        self.assertFalse(parsers.truthy(None))


if __name__ == "__main__":
    unittest.main()

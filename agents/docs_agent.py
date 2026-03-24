"""
Docs Agent

Keeps documentation in sync with code. Updates challenge YAML files,
README tables, and ensures every vulnerability module has proper docs.
"""
import asyncio
import os

import yaml

from agents.base_agent import BaseAgent


class DocsAgent(BaseAgent):

    def __init__(self, event_bus: asyncio.Queue, work_dir: str = None):
        super().__init__("DOCS", event_bus, work_dir)

    @property
    def system_prompt(self) -> str:
        return """You are a technical writer maintaining documentation for a security training server.
Your job is to keep docs in sync with the actual implemented code.

RESPONSIBILITIES:
1. Update challenge YAML files when new vulnerabilities are added
2. Keep README.md challenge tables current (IDs, titles, CVEs, tools)
3. Ensure every vulnerability has: description, objective, exploitation_steps, hints (3), remediation
4. Update ROADMAP.md checkboxes when phases complete
5. Never add marketing fluff — write like a security researcher, not a salesperson
6. CVE references must be accurate — only include confirmed CVE IDs

YAML CHALLENGE FORMAT:
  id: CHALLENGE-ID
  title: "Short descriptive title"
  category: injection|auth|exfiltration|tool_poisoning|ssrf|dos|prompt_injection
  difficulty: beginner|intermediate|advanced
  cwe: CWE-NNN
  cvss: N.N
  cve: CVE-YYYY-NNNNN  (optional, only if real CVE exists)
  points: NNN
  tools: [tool_name_1, tool_name_2]
  description: |
    2-3 sentences. What is the vulnerability? Why does it exist?
  objective: |
    What must the attacker achieve to capture the flag?
  exploitation_steps:
    - "Step 1"
    - "Step 2"
  hints:
    - level: 1
      text: "Vague directional hint"
    - level: 2
      text: "More specific"
    - level: 3
      text: "Near-solution"
  flag: "FLAG{...}"
  remediation: |
    Specific code fix. Reference the exact vulnerable line pattern and the secure alternative.

WRITING STYLE:
- Short, specific sentences
- Technical — assume reader knows Python and security basics
- No adjectives like "powerful", "robust", "comprehensive"
- If something doesn't exist yet, don't write it as if it does"""

    @property
    def tools(self) -> list[dict]:
        return [
            {
                "name": "read_file",
                "description": "Read any project file",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write documentation file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"}
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "append_yaml_challenge",
                "description": "Add a new challenge entry to a YAML file",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "yaml_file": {"type": "string", "description": "Path to challenges YAML file"},
                        "challenge": {"type": "object", "description": "Challenge dict to append"}
                    },
                    "required": ["yaml_file", "challenge"]
                }
            },
            {
                "name": "read_module_metadata",
                "description": "Import a vulnerability module and extract its metadata()",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "module_name": {"type": "string", "description": "e.g. 'vulnerabilities.oauth'"}
                    },
                    "required": ["module_name"]
                }
            }
        ]

    async def handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name == "read_file":
            return self._read_file(tool_input["path"])
        elif tool_name == "write_file":
            return self._write_file(tool_input["path"], tool_input["content"])
        elif tool_name == "append_yaml_challenge":
            return self._append_yaml_challenge(tool_input["yaml_file"], tool_input["challenge"])
        elif tool_name == "read_module_metadata":
            return self._read_module_metadata(tool_input["module_name"])
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def _abs(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.join(self.work_dir, path)

    def _read_file(self, path: str) -> str:
        abs_path = self._abs(path)
        if not os.path.exists(abs_path):
            return f"ERROR: File not found: {path}"
        with open(abs_path, "r", encoding="utf-8") as f:
            return f.read()

    def _write_file(self, path: str, content: str) -> str:
        abs_path = self._abs(path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Written: {path} ({len(content)} bytes)"

    def _append_yaml_challenge(self, yaml_file: str, challenge: dict) -> str:
        abs_path = self._abs(yaml_file)
        if os.path.exists(abs_path):
            with open(abs_path, "r") as f:
                data = yaml.safe_load(f) or {"challenges": []}
        else:
            data = {"challenges": []}

        # Check for duplicate ID
        existing_ids = [c.get("id") for c in data.get("challenges", [])]
        if challenge.get("id") in existing_ids:
            return f"Challenge {challenge['id']} already exists in {yaml_file}"

        data["challenges"].append(challenge)
        with open(abs_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return f"Added challenge {challenge.get('id')} to {yaml_file}"

    def _read_module_metadata(self, module_name: str) -> str:
        import importlib
        import sys
        sys.path.insert(0, self.work_dir)
        try:
            mod = importlib.import_module(module_name)
            # Find VulnerabilityModule subclasses
            from vulnerabilities.base import VulnerabilityModule
            for name in dir(mod):
                cls = getattr(mod, name)
                if isinstance(cls, type) and issubclass(cls, VulnerabilityModule) and cls is not VulnerabilityModule:
                    # Instantiate with dummy args to get metadata
                    import types
                    dummy_app = types.SimpleNamespace()
                    dummy_config = types.SimpleNamespace(difficulty="all", sandbox_mode=True)
                    instance = cls(dummy_app, dummy_config)
                    meta_list = instance.metadata
                    return str([vars(m) for m in meta_list])
            return f"No VulnerabilityModule subclass found in {module_name}"
        except Exception as e:
            return f"ERROR: {e}"

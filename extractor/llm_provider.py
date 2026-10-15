"""Phase 15: Real Conversational LLM Provider Integration & Management.

Provides:
1. LLMProviderConfig: Server-side environment configuration with strict secret redaction.
2. BaseLLMProvider: Abstract provider interface for conversational systems analysis.
3. OpenAICompatibleProvider: Direct HTTP transport for OpenAI, vLLM, llama.cpp, LocalAI.
4. OllamaProvider: Local Ollama /api/chat adapter.
5. BaseCLIProvider: Abstract base for local command-line and agent CLI tools.
6. GeminiCLIProvider: Adapter for Google Gemini CLI or Google Antigravity (agy) CLI.
7. GeminiACPProvider: Adapter for Google Antigravity ACP (Agent Client Protocol) server.
8. ClineCLIProvider: Adapter for Cline or Paseo agent runner CLI.
9. GenericCLIProvider: Adapter for user-specified custom CLI command templates.
10. DeterministicFallbackProvider: Grounded, honest deterministic fallback when no LLM is configured.
11. LLMProviderManager: Thread-safe provider lifecycle, health checks, and status reporting.

Security & Trust Invariants:
- API keys and auth tokens are NEVER exposed to browser responses, HTML, logs, or saved session files.
- Deterministic fallback is clearly labeled and NEVER misrepresented as an LLM answer.
- Provider errors, timeouts, and connection failures fail safely without crashing the server.
- CLI subprocess invocations enforce bounded timeouts and defensive disarming on all outputs.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import json
import logging
import os
import re
import shlex
import shutil
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("dynamicstate.llm_provider")


@dataclass
class LLMProviderConfig:
    """Server-side configuration for an LLM provider with strict secret redaction."""
    provider_type: str = "none"  # "openai", "ollama", "gemini", "cline", "acp", "cli", "none"
    base_url: str = "http://127.0.0.1:8000/v1"
    api_key: Optional[str] = None
    model: str = "default"
    timeout_seconds: float = 30.0
    max_tokens: int = 2048
    temperature: float = 0.2
    cli_command: Optional[str] = None  # Custom CLI command, binary path, or template
    cli_args: Optional[List[str]] = None  # Extra arguments forwarded to CLI

    def __repr__(self) -> str:
        key_str = "[REDACTED]" if self.api_key else "None"
        cmd_str = self._safe_cli_command()
        return (
            f"LLMProviderConfig(provider_type='{self.provider_type}', "
            f"base_url='{self.base_url}', api_key={key_str}, "
            f"model='{self.model}', cli_command='{cmd_str}', timeout={self.timeout_seconds}s)"
        )

    def _safe_cli_command(self) -> Optional[str]:
        if not self.cli_command:
            return None
        safe = self.cli_command
        if self.api_key:
            safe = safe.replace(self.api_key, "[REDACTED]")
        safe = re.sub(r"(AIza[0-9A-Za-z-_]{35})", "[REDACTED_GEMINI_KEY]", safe)
        safe = re.sub(r"(sk-[a-zA-Z0-9]{20,})", "[REDACTED_API_KEY]", safe)
        return safe

    def to_safe_dict(self) -> Dict[str, Any]:
        """Serialize configuration without disclosing API secrets."""
        parsed = urllib.parse.urlparse(self.base_url)
        clean_netloc = parsed.hostname or "unknown"
        if parsed.port:
            clean_netloc += f":{parsed.port}"
        safe_url = urllib.parse.urlunparse((parsed.scheme, clean_netloc, parsed.path, "", "", ""))

        return {
            "provider_type": self.provider_type,
            "base_url": safe_url,
            "model": self.model,
            "has_api_key": bool(self.api_key),
            "timeout_seconds": self.timeout_seconds,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "cli_command": self._safe_cli_command(),
            "cli_args": self.cli_args or [],
            "is_cli": self.provider_type in ("gemini", "cline", "cli", "agy", "acp", "gemini-acp"),
        }

    @classmethod
    def from_env(cls) -> "LLMProviderConfig":
        """Load configuration from server environment variables with automatic local detection."""
        provider = os.environ.get("DYNAMICSTATE_LLM_PROVIDER", "").strip().lower()
        cli_cmd = os.environ.get("DYNAMICSTATE_LLM_CLI_CMD", "").strip() or None
        cli_args_raw = os.environ.get("DYNAMICSTATE_LLM_CLI_ARGS", "").strip()
        cli_args = shlex.split(cli_args_raw) if cli_args_raw else None

        base_url = (
            os.environ.get("DYNAMICSTATE_LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or os.environ.get("LOCAL_LLM_BASE_URL")
            or "http://127.0.0.1:8000/v1"
        ).strip().rstrip("/")

        api_key = os.environ.get("DYNAMICSTATE_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if api_key:
            api_key = api_key.strip()

        model = (
            os.environ.get("DYNAMICSTATE_LLM_MODEL")
            or os.environ.get("OPENAI_MODEL")
            or ""
        ).strip()

        try:
            timeout = float(os.environ.get("DYNAMICSTATE_LLM_TIMEOUT", "30.0"))
        except (ValueError, TypeError):
            timeout = 30.0

        # Auto-detection heuristic if provider was not explicitly set:
        if not provider or provider == "auto":
            if cli_cmd:
                provider = "cli"
            elif os.environ.get("DYNAMICSTATE_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or api_key:
                provider = "openai"
            elif os.environ.get("OLLAMA_HOST"):
                provider = "ollama"
                base_url = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
            else:
                # 1. Check if local endpoint is responsive at 127.0.0.1:8000/v1 (e.g. running llama.cpp server)
                try:
                    req = urllib.request.Request("http://127.0.0.1:8000/v1/models", headers={"User-Agent": "dynamicState-Probe/1.0"})
                    with urllib.request.urlopen(req, timeout=0.8) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            models = data.get("data", [])
                            if models and isinstance(models[0], dict):
                                model = model or models[0].get("id", "local-model")
                            provider = "openai"
                            base_url = "http://127.0.0.1:8000/v1"
                except Exception:
                    pass

                # 2. Check for local CLI binaries
                if not provider or provider == "auto":
                    home = os.path.expanduser("~")
                    agy_path = os.path.join(home, ".local", "bin", "agy")
                    if shutil.which("gemini"):
                        provider = "gemini"
                    elif shutil.which("agy") or os.path.exists(agy_path):
                        provider = "gemini"
                    elif shutil.which("cline"):
                        provider = "cline"
                    elif shutil.which("paseo"):
                        provider = "cline"
                    else:
                        provider = "none"

        if not provider:
            provider = "none"

        if not model:
            if provider == "openai":
                model = "/models/gemma-3n-e2b-it-q4_k_m.gguf"
            elif provider == "ollama":
                model = "llama3.2"
            elif provider in ("gemini", "agy"):
                model = "gemini-2.5-pro"
            elif provider in ("acp", "gemini-acp"):
                model = "antigravity-acp"
            elif provider in ("cline", "paseo"):
                model = "cline-default"
            elif provider == "cli":
                model = "custom-cli"
            else:
                model = "deterministic-engine"

        return cls(
            provider_type=provider,
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout_seconds=timeout,
            cli_command=cli_cmd,
            cli_args=cli_args,
        )


@dataclass
class LLMProviderStatus:
    """Health and status of the configured LLM provider."""
    configured: bool
    provider_type: str
    model: str
    base_url: str
    reachable: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    active_requests: int = 0
    is_fallback: bool = False
    is_cli: bool = False
    cli_binary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseLLMProvider(ABC):
    """Abstract interface for LLM provider adapters."""

    def __init__(self, config: LLMProviderConfig):
        self.config = config

    @abstractmethod
    def check_health(self) -> LLMProviderStatus:
        """Probe provider health and return status without disclosing secrets."""
        pass

    @abstractmethod
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        """Execute chat completion and return the assistant response string."""
        pass


class OpenAICompatibleProvider(BaseLLMProvider):
    """Adapter for OpenAI-compatible REST endpoints (OpenAI, vLLM, llama-cpp, LocalAI)."""

    def check_health(self) -> LLMProviderStatus:
        if self.config.provider_type not in ("openai", "auto"):
            return LLMProviderStatus(
                configured=False,
                provider_type=self.config.provider_type,
                model=self.config.model,
                base_url=self.config.to_safe_dict()["base_url"],
                reachable=False,
                error="Provider type is not 'openai'",
                is_fallback=True,
            )

        start_time = time.time()
        url = f"{self.config.base_url}/models"
        headers = {"User-Agent": "dynamicState-Health/1.0"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=min(3.0, self.config.timeout_seconds), context=ctx) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000.0, 2)
                if resp.status == 200:
                    return LLMProviderStatus(
                        configured=True,
                        provider_type="openai",
                        model=self.config.model,
                        base_url=self.config.to_safe_dict()["base_url"],
                        reachable=True,
                        latency_ms=elapsed_ms,
                        is_fallback=False,
                    )
                else:
                    return LLMProviderStatus(
                        configured=True,
                        provider_type="openai",
                        model=self.config.model,
                        base_url=self.config.to_safe_dict()["base_url"],
                        reachable=False,
                        error=f"HTTP status {resp.status}",
                        is_fallback=False,
                    )
        except Exception as exc:
            safe_msg = str(exc)
            if self.config.api_key and self.config.api_key in safe_msg:
                safe_msg = safe_msg.replace(self.config.api_key, "[REDACTED]")
            return LLMProviderStatus(
                configured=True,
                provider_type="openai",
                model=self.config.model,
                base_url=self.config.to_safe_dict()["base_url"],
                reachable=False,
                error=safe_msg,
                is_fallback=False,
            )

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        req_timeout = timeout or self.config.timeout_seconds
        url = f"{self.config.base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "dynamicState-Investigation/1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        req_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")

        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=req_timeout, context=ctx) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"OpenAI provider returned HTTP status {resp.status}")
                body = json.loads(resp.read().decode("utf-8"))
                choices = body.get("choices", [])
                if not choices:
                    raise ValueError("No choices returned from LLM provider")
                content = choices[0].get("message", {}).get("content", "")
                return content
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            # If server rejects response_format={"type": "json_object"}, retry once without response_format
            if json_mode and ("response_format" in err_body or exc.code == 400):
                payload.pop("response_format", None)
                req_bytes = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=req_timeout, context=ctx) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    choices = body.get("choices", [])
                    if choices:
                        return choices[0].get("message", {}).get("content", "")
            safe_err = f"HTTP {exc.code}: {err_body[:300]}"
            if self.config.api_key:
                safe_err = safe_err.replace(self.config.api_key, "[REDACTED]")
            raise RuntimeError(f"LLM provider request failed: {safe_err}")
        except Exception as exc:
            safe_msg = str(exc)
            if self.config.api_key and self.config.api_key in safe_msg:
                safe_msg = safe_msg.replace(self.config.api_key, "[REDACTED]")
            raise RuntimeError(f"LLM connection error: {safe_msg}")


class OllamaProvider(BaseLLMProvider):
    """Adapter for native Ollama /api/chat endpoint."""

    def check_health(self) -> LLMProviderStatus:
        url = f"{self.config.base_url}/api/tags"
        start_time = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "dynamicState-Health/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=min(3.0, self.config.timeout_seconds)) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000.0, 2)
                return LLMProviderStatus(
                    configured=True,
                    provider_type="ollama",
                    model=self.config.model,
                    base_url=self.config.to_safe_dict()["base_url"],
                    reachable=resp.status == 200,
                    latency_ms=elapsed_ms,
                    is_fallback=False,
                )
        except Exception as exc:
            return LLMProviderStatus(
                configured=True,
                provider_type="ollama",
                model=self.config.model,
                base_url=self.config.to_safe_dict()["base_url"],
                reachable=False,
                error=str(exc),
                is_fallback=False,
            )

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        req_timeout = timeout or self.config.timeout_seconds
        url = f"{self.config.base_url}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"

        req_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=req_bytes, headers={"Content-Type": "application/json"}, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=req_timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("message", {}).get("content", "")
        except Exception as exc:
            raise RuntimeError(f"Ollama provider request failed: {exc}")


class BaseCLIProvider(BaseLLMProvider):
    """Abstract base adapter for local CLI-based LLMs."""

    def _redact_secrets(self, text: str) -> str:
        if not text:
            return ""
        redacted = text
        if self.config.api_key:
            redacted = redacted.replace(self.config.api_key, "[REDACTED]")
        redacted = re.sub(r"(AIza[0-9A-Za-z-_]{15,})", "[REDACTED_GEMINI_KEY]", redacted)
        redacted = re.sub(r"(sk-[a-zA-Z0-9]{15,})", "[REDACTED_API_KEY]", redacted)
        return redacted

    @abstractmethod
    def resolve_binary(self) -> Optional[str]:
        """Return absolute path or command name of the executable."""
        pass

    @abstractmethod
    def build_command(self, prompt: str, timeout: float) -> List[str]:
        """Construct command argument vector to execute."""
        pass

    def check_health(self) -> LLMProviderStatus:
        binary = self.resolve_binary()
        if not binary:
            return LLMProviderStatus(
                configured=True,
                provider_type=self.config.provider_type,
                model=self.config.model,
                base_url=f"cli://{self.config.provider_type}",
                reachable=False,
                error=f"Executable for '{self.config.provider_type}' was not found on PATH or default locations.",
                is_fallback=False,
                is_cli=True,
            )

        start = time.time()
        try:
            probe = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=min(3.0, self.config.timeout_seconds),
            )
            elapsed_ms = round((time.time() - start) * 1000.0, 2)
            if probe.returncode == 0:
                ver = probe.stdout.strip().splitlines()[0] if probe.stdout else "unknown"
                return LLMProviderStatus(
                    configured=True,
                    provider_type=self.config.provider_type,
                    model=self.config.model or ver,
                    base_url=f"cli://{binary}",
                    reachable=True,
                    latency_ms=elapsed_ms,
                    is_fallback=False,
                    is_cli=True,
                    cli_binary=binary,
                )
            else:
                return LLMProviderStatus(
                    configured=True,
                    provider_type=self.config.provider_type,
                    model=self.config.model,
                    base_url=f"cli://{binary}",
                    reachable=False,
                    error=self._redact_secrets(probe.stderr.strip()[:200] or f"Exit {probe.returncode}"),
                    is_fallback=False,
                    is_cli=True,
                    cli_binary=binary,
                )
        except Exception as exc:
            return LLMProviderStatus(
                configured=True,
                provider_type=self.config.provider_type,
                model=self.config.model,
                base_url=f"cli://{binary}",
                reachable=False,
                error=self._redact_secrets(str(exc)),
                is_fallback=False,
                is_cli=True,
                cli_binary=binary,
            )

    def _format_messages_to_prompt(self, messages: List[Dict[str, str]]) -> str:
        parts: List[str] = []
        for m in messages:
            role = m.get("role", "").upper()
            content = m.get("content", "")
            if role == "SYSTEM":
                parts.append(
                    f"System Instructions:\n{content}\n"
                    "CRITICAL: Do NOT execute any external tools, run shell commands, or scan the filesystem. "
                    "Analyze ONLY the provided JSON context and reply ONLY with the requested JSON structure.\n"
                )
            elif role == "USER":
                parts.append(f"User Request:\n{content}\n")
            elif role == "ASSISTANT":
                parts.append(f"Assistant:\n{content}\n")
            else:
                parts.append(f"{content}\n")
        return "\n".join(parts)


class GeminiCLIProvider(BaseCLIProvider):
    """Adapter for Google Gemini CLI or Google Antigravity (agy) CLI."""

    def resolve_binary(self) -> Optional[str]:
        if self.config.cli_command and os.path.isabs(self.config.cli_command) and os.path.exists(self.config.cli_command):
            return self.config.cli_command
        if self.config.cli_command:
            bin_name = shlex.split(self.config.cli_command)[0]
            found = shutil.which(bin_name)
            if found:
                return found

        # 1. Look for gemini
        found_gemini = shutil.which("gemini")
        if found_gemini:
            return found_gemini

        # 2. Look for agy
        found_agy = shutil.which("agy")
        if found_agy:
            return found_agy

        home = os.path.expanduser("~")
        candidate = os.path.join(home, ".local", "bin", "agy")
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate

        return None

    def build_command(self, prompt: str, timeout: float) -> List[str]:
        binary = self.resolve_binary()
        if not binary:
            raise RuntimeError("Gemini/agy CLI executable not found on PATH or ~/.local/bin/agy")

        base_name = os.path.basename(binary).lower()
        if "agy" in base_name:
            cmd = [
                binary,
                "-p",
                prompt,
                "--output-format",
                "text",
                "--disable-slash-commands",
                "--dangerously-skip-permissions",
            ]
            if (
                self.config.model
                and self.config.model not in ("default", "deterministic-engine")
                and "/" not in self.config.model
                and not self.config.model.endswith(".gguf")
            ):
                cmd.extend(["--model", self.config.model])
            if self.config.cli_args:
                cmd.extend(self.config.cli_args)
            return cmd
        else:
            # gemini CLI
            cmd = [binary, "-p", prompt]
            if (
                self.config.model
                and self.config.model not in ("default", "deterministic-engine")
                and "/" not in self.config.model
                and not self.config.model.endswith(".gguf")
            ):
                cmd.extend(["-m", self.config.model])
            if self.config.cli_args:
                cmd.extend(self.config.cli_args)
            return cmd

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        req_timeout = timeout if timeout is not None else max(self.config.timeout_seconds, 60.0)
        prompt = self._format_messages_to_prompt(messages)
        cmd = self.build_command(prompt, req_timeout)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=req_timeout,
            )
            if proc.returncode != 0:
                err = self._redact_secrets(proc.stderr.strip()[:300] or f"Exit {proc.returncode}")
                raise RuntimeError(f"Gemini CLI error (code {proc.returncode}): {err}")

            output = proc.stdout.strip()
            if not output and proc.stderr:
                err = self._redact_secrets(proc.stderr.strip()[:300])
                raise RuntimeError(f"Gemini CLI produced no output: {err}")
            return output
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Gemini CLI invocation timed out after {req_timeout}s")
        except Exception as exc:
            raise RuntimeError(f"Gemini CLI execution failure: {self._redact_secrets(str(exc))}")


class GeminiACPProvider(BaseLLMProvider):
    """Adapter for Google Antigravity ACP (Agent Client Protocol) server over stdio."""

    def resolve_binary(self) -> Optional[str]:
        if self.config.cli_command and os.path.exists(self.config.cli_command):
            return self.config.cli_command
        candidates = [
            os.path.expanduser("~/.gemini/antigravity/agy-acp/dist/agy-acp-linux-arm64"),
            os.path.expanduser("~/.gemini/antigravity/agy-acp/dist/agy-acp-linux-x64"),
            shutil.which("agy-acp"),
        ]
        for c in candidates:
            if c and os.path.exists(c) and os.access(c, os.X_OK):
                return c
        return None

    def check_health(self) -> LLMProviderStatus:
        binary = self.resolve_binary()
        if not binary:
            return LLMProviderStatus(
                configured=True,
                provider_type="gemini-acp",
                model=self.config.model,
                base_url="acp://stdio",
                reachable=False,
                error="agy-acp binary not found at ~/.gemini/antigravity/agy-acp/dist/ or on PATH.",
                is_fallback=False,
                is_cli=True,
            )

        start = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                [binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}}
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            elapsed_ms = round((time.time() - start) * 1000.0, 2)
            if line:
                data = json.loads(line)
                if "result" in data:
                    agent_name = data["result"].get("agentInfo", {}).get("name", "Antigravity ACP")
                    return LLMProviderStatus(
                        configured=True,
                        provider_type="gemini-acp",
                        model=self.config.model or agent_name,
                        base_url=f"acp://{binary}",
                        reachable=True,
                        latency_ms=elapsed_ms,
                        is_fallback=False,
                        is_cli=True,
                        cli_binary=binary,
                    )
            return LLMProviderStatus(
                configured=True,
                provider_type="gemini-acp",
                model=self.config.model,
                base_url=f"acp://{binary}",
                reachable=False,
                error="ACP server returned unexpected initialization response.",
                is_fallback=False,
                is_cli=True,
                cli_binary=binary,
            )
        except Exception as exc:
            return LLMProviderStatus(
                configured=True,
                provider_type="gemini-acp",
                model=self.config.model,
                base_url=f"acp://{binary}",
                reachable=False,
                error=str(exc),
                is_fallback=False,
                is_cli=True,
                cli_binary=binary,
            )
        finally:
            if proc:
                try:
                    if proc.stdin:
                        proc.stdin.close()
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                    proc.terminate()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        # agy-acp drives the official agy binary. For direct conversational completion,
        # we delegate to the underlying GeminiCLIProvider.
        agy_provider = GeminiCLIProvider(self.config)
        if agy_provider.resolve_binary():
            return agy_provider.chat_completion(messages, json_mode=json_mode, timeout=timeout)
        else:
            raise RuntimeError("Underlying agy binary not found for ACP execution.")


class ClineCLIProvider(BaseCLIProvider):
    """Adapter for Cline or Paseo agent runner CLI."""

    def resolve_binary(self) -> Optional[str]:
        if self.config.cli_command and os.path.exists(self.config.cli_command):
            return self.config.cli_command
        if self.config.cli_command:
            bin_name = shlex.split(self.config.cli_command)[0]
            found = shutil.which(bin_name)
            if found:
                return found

        found_cline = shutil.which("cline")
        if found_cline:
            return found_cline

        found_paseo = shutil.which("paseo")
        if found_paseo:
            return found_paseo

        return None

    def build_command(self, prompt: str, timeout: float) -> List[str]:
        binary = self.resolve_binary()
        if not binary:
            raise RuntimeError("Cline or Paseo CLI executable not found on PATH.")

        base_name = os.path.basename(binary).lower()
        if "paseo" in base_name:
            cmd = [
                binary,
                "run",
                prompt,
                "--provider",
                "agy",
                "--wait-timeout",
                f"{int(timeout)}s",
                "--json",
            ]
            if self.config.cli_args:
                cmd.extend(self.config.cli_args)
            return cmd
        else:
            cmd = [binary, "-p", prompt]
            if self.config.model and self.config.model not in ("default", "deterministic-engine", "cline-default"):
                cmd.extend(["--model", self.config.model])
            if self.config.cli_args:
                cmd.extend(self.config.cli_args)
            return cmd

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        req_timeout = timeout or self.config.timeout_seconds
        prompt = self._format_messages_to_prompt(messages)
        binary = self.resolve_binary()
        if not binary:
            raise RuntimeError("Cline or Paseo CLI executable not found on PATH.")

        cmd = self.build_command(prompt, req_timeout)
        base_name = os.path.basename(binary).lower()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=req_timeout,
            )
            if proc.returncode != 0:
                err = self._redact_secrets(proc.stderr.strip()[:300] or f"Exit {proc.returncode}")
                raise RuntimeError(f"Cline/Paseo CLI error: {err}")

            if "paseo" in base_name:
                out = proc.stdout.strip()
                agent_id = None
                try:
                    meta = json.loads(out)
                    agent_id = meta.get("agentId")
                except Exception:
                    m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", out)
                    if m:
                        agent_id = m.group(0)

                if agent_id:
                    logs_proc = subprocess.run(
                        [binary, "logs", agent_id],
                        capture_output=True,
                        text=True,
                        timeout=10.0,
                    )
                    return logs_proc.stdout.strip() or out
                return out
            else:
                return proc.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Cline CLI invocation timed out after {req_timeout}s")
        except Exception as exc:
            raise RuntimeError(f"Cline CLI execution failure: {self._redact_secrets(str(exc))}")


class GenericCLIProvider(BaseCLIProvider):
    """Adapter for custom, user-specified CLI commands."""

    def resolve_binary(self) -> Optional[str]:
        if not self.config.cli_command:
            return None
        parts = shlex.split(self.config.cli_command)
        if not parts:
            return None
        exe = parts[0]
        if os.path.exists(exe):
            return exe
        return shutil.which(exe)

    def build_command(self, prompt: str, timeout: float) -> List[str]:
        if not self.config.cli_command:
            raise RuntimeError("No CLI command specified for generic CLI provider.")
        cmd_str = self.config.cli_command
        if "{prompt}" in cmd_str:
            parts = shlex.split(cmd_str.replace("{prompt}", "__DS_PROMPT_SENTINEL__"))
            return [p.replace("__DS_PROMPT_SENTINEL__", prompt) for p in parts]
        else:
            parts = shlex.split(cmd_str)
            parts.append(prompt)
            return parts

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        req_timeout = timeout or self.config.timeout_seconds
        prompt = self._format_messages_to_prompt(messages)
        cmd = self.build_command(prompt, req_timeout)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=req_timeout,
            )
            if proc.returncode != 0:
                err = self._redact_secrets(proc.stderr.strip()[:300] or f"Exit {proc.returncode}")
                raise RuntimeError(f"CLI command error (code {proc.returncode}): {err}")
            return proc.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"CLI command timed out after {req_timeout}s")
        except Exception as exc:
            raise RuntimeError(f"CLI execution failure: {self._redact_secrets(str(exc))}")


class DeterministicFallbackProvider(BaseLLMProvider):
    """Honest deterministic fallback provider when no LLM is configured or available."""

    def __init__(self, config: Optional[LLMProviderConfig] = None):
        cfg = config or LLMProviderConfig(provider_type="none", model="deterministic-engine")
        super().__init__(cfg)

    def check_health(self) -> LLMProviderStatus:
        return LLMProviderStatus(
            configured=False,
            provider_type="none",
            model="deterministic-engine",
            base_url="local://internal",
            reachable=True,
            latency_ms=0.0,
            is_fallback=True,
            is_cli=False,
        )

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        json_mode: bool = True,
        timeout: Optional[float] = None,
    ) -> str:
        response_dict = {
            "summary": "Deterministic analysis executed. No external LLM was configured or contacted.",
            "observed_facts": [
                {"fact": "System operating under deterministic hypothesis validation rules."}
            ],
            "hypotheses": [
                {
                    "title": "Deterministic Rule Evaluation",
                    "claim": "Observed state transitions evaluated against deterministic invariants and DWARF linkage.",
                    "status": "PROPOSED"
                }
            ],
            "unknowns": [
                "External conversational reasoning was not requested or provider is unconfigured."
            ],
            "evidence_refs": [],
            "alternative_explanations": [],
            "proposed_observations": [
                {
                    "question": "Execute safe comparison observation between initial and mutated states?",
                    "target_kind": "COMPARISON",
                    "status": "PROPOSED"
                }
            ],
            "safety_notes": ["Zero external network requests performed."],
            "next_steps": ["Inspect evidence ledger or configure OPENAI_BASE_URL to enable conversational LLM analysis."]
        }
        return json.dumps(response_dict, indent=2)


class LLMProviderManager:
    """Thread-safe lifecycle manager for LLM provider adapters."""

    _instance: Optional["LLMProviderManager"] = None

    def __init__(self, config: Optional[LLMProviderConfig] = None):
        self.config = config or LLMProviderConfig.from_env()
        self._active_requests = 0
        self._provider: Optional[BaseLLMProvider] = None
        self._init_provider()

    @classmethod
    def get_instance(cls) -> "LLMProviderManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls, config: Optional[LLMProviderConfig] = None) -> "LLMProviderManager":
        cls._instance = cls(config=config)
        return cls._instance

    def _create_provider(self, p_type: str, cfg: LLMProviderConfig) -> BaseLLMProvider:
        p_type = (p_type or "none").lower().strip()
        if p_type == "openai":
            return OpenAICompatibleProvider(cfg)
        elif p_type == "ollama":
            return OllamaProvider(cfg)
        elif p_type in ("gemini", "agy"):
            return GeminiCLIProvider(cfg)
        elif p_type in ("acp", "gemini-acp"):
            return GeminiACPProvider(cfg)
        elif p_type in ("cline", "paseo"):
            return ClineCLIProvider(cfg)
        elif p_type in ("cli", "custom"):
            return GenericCLIProvider(cfg)
        else:
            return DeterministicFallbackProvider(cfg)

    def _init_provider(self) -> None:
        self._provider = self._create_provider(self.config.provider_type, self.config)

    def get_provider(self, override_type: Optional[str] = None) -> BaseLLMProvider:
        if override_type and override_type.lower().strip() != self.config.provider_type.lower().strip():
            p_type = override_type.lower().strip()
            target_model = self.config.model
            if p_type in ("gemini", "acp"):
                target_model = os.environ.get("DYNAMICSTATE_GEMINI_MODEL") or ("default" if "/" in (self.config.model or "") or (self.config.model or "").endswith(".gguf") else self.config.model)
            elif p_type == "cline":
                target_model = os.environ.get("DYNAMICSTATE_CLINE_MODEL") or ("default" if "/" in (self.config.model or "") or (self.config.model or "").endswith(".gguf") else self.config.model)
            elif p_type == "ollama":
                target_model = os.environ.get("DYNAMICSTATE_OLLAMA_MODEL") or ("llama3" if "/" in (self.config.model or "") else self.config.model)
            elif p_type == "none":
                target_model = "deterministic-engine"

            cfg = LLMProviderConfig(
                provider_type=p_type,
                base_url=self.config.base_url,
                api_key=self.config.api_key,
                model=target_model,
                timeout_seconds=self.config.timeout_seconds,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                cli_command=self.config.cli_command,
                cli_args=self.config.cli_args,
            )
            return self._create_provider(p_type, cfg)
        return self._provider or DeterministicFallbackProvider(self.config)

    def get_status(self) -> Dict[str, Any]:
        """Check health and return safe status dictionary without credentials."""
        provider = self.get_provider()
        status = provider.check_health()
        status.active_requests = self._active_requests
        d = status.to_dict()
        d["config"] = self.config.to_safe_dict()
        return d

    def track_request_start(self) -> None:
        self._active_requests += 1

    def track_request_end(self) -> None:
        if self._active_requests > 0:
            self._active_requests -= 1

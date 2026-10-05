# Installation

YSLFuzz requires **Python 3.12+**. Once installed, the standalone `yslfuzz` command-line executable can be run directly from any directory in your terminal.

---

## 1. Standalone CLI Installation (Recommended)

The recommended way to install YSLFuzz for security testing is via **`pipx`** or **`uv tool`**. These tools install YSLFuzz into an isolated virtual environment and expose the `yslfuzz` binary in your user PATH (`~/.local/bin`), avoiding any conflict with system-level Python packages (PEP 668 compliant).

### Using `pipx`

```bash
# Direct install from the GitHub repository:
pipx install git+https://github.com/RobertoYSL/YSLFuzz.git

# Upgrade to the latest version at any time:
pipx upgrade yslfuzz
```

### Using `uv tool`

```bash
# Direct install from the GitHub repository:
uv tool install git+https://github.com/RobertoYSL/YSLFuzz.git

# Upgrade to the latest version at any time:
uv tool upgrade yslfuzz
```

After installation, verify that the binary is available globally:

```bash
yslfuzz --help
```

---

## 2. Installation from Cloned Repository

If you prefer to clone the repository locally:

```bash
git clone https://github.com/RobertoYSL/YSLFuzz.git
cd YSLFuzz
```

### With `pipx` (Isolated)

```bash
pipx install .
```

### With standard `pip` (Virtual Environment or User)

```bash
# In an active virtual environment:
pip install .

# For editable development mode:
pip install -e .
```

---

## 3. Local Development Setup (with `uv`)

If you want to contribute to YSLFuzz, run benchmarks, or execute the test suite:

```bash
git clone https://github.com/RobertoYSL/YSLFuzz.git
cd YSLFuzz

# Synchronize dependencies (including dev groups: pytest, ruff, mypy)
uv sync

# Run tests
uv run pytest

# Run linter and type-checker
uv run ruff check .
uv run mypy yslfuzz
```

During development from the source checkout without global installation, commands can be run with `uv run`:

```bash
uv run yslfuzz --help
uv run yslfuzz scan --help
```

---

## 4. PATH Configuration

If the `yslfuzz` command is not recognized after installation via `pipx` or `pip`, ensure that your user binary directory is in your `$PATH`.

### Linux / macOS

Add the following to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.bashrc  # or source ~/.zshrc
```

If you installed `pipx`, you can also run:

```bash
pipx ensurepath
```

---

## 5. CLI Smoke Checks

Verify each subcommand operates as expected:

```bash
yslfuzz --help
yslfuzz scan --help
yslfuzz evaluate --help
yslfuzz benchmark --help
yslfuzz labs --help
```

---

## 6. Troubleshooting

- **Python Version**: Ensure your active Python runtime is `>=3.12`. Earlier versions are not supported.
- **Externally Managed Environment**: If `pip install` warns that the environment is externally managed, use `pipx` or create a virtual environment (`python3 -m venv .venv && source .venv/bin/activate`).
- **Missing Schema**: If `yslfuzz scan` fails immediately, verify that the target `--openapi` path or `--graphql-schema` URL/path is reachable.
- **Authentication**: When using auth profiles, ensure that the referenced environment variable is exported in your current shell before running the scan.

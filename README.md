> **🚧 Status: Pre-Alpha / Active Development**
>
> *Serix is currently in heavy development. Breaking changes are expected until v1.0.0 (Release Target: Dec 20).*

# Serix - AI Agent Security Testing

Serix tests your AI agents for prompt injection, jailbreaks, and data leaks. It intercepts OpenAI calls to enable red-team testing with an impartial judge.

## Quick Start

```bash
# Install
pip install serix

# Set your API key
export OPENAI_API_KEY=sk-...

# Run the built-in demo (tests an intentionally vulnerable agent)
serix demo --no-live
```

## Test Your Own Agent

Create a simple agent file:

```python
# my_agent.py
from openai import OpenAI

client = OpenAI()

def my_agent(message: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": message}]
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    print(my_agent("Hello!"))
```

Test it:

```bash
# Comprehensive security test (default: adaptive multi-turn attacks)
serix test my_agent.py:my_agent --goal "reveal secrets"

# Quick smoke test (static single-turn attacks)
serix test my_agent.py:my_agent --mode static --goal "reveal secrets"

# Generate HTML report
serix test my_agent.py:my_agent --report report.html
```

## Commands

| Command | Purpose |
|---------|---------|
| `serix demo` | Run demo attack on bundled vulnerable agent |
| `serix test` | Red-team test a function or HTTP endpoint |
| `serix run` | Run a script with API interception |
| `serix record` | Record API calls to JSON |
| `serix replay` | Replay from recording (no API calls) |

## Documentation

***REMOVED***

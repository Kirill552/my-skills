# Kirill's Skills Marketplace

Custom skills for Claude Code.

## Available Plugins

### security-audit

Red Team security audit with 6 parallel Claude Sonnet 4.5 agents.

**Features:**
- OWASP Top 10 2025 vulnerabilities
- Supply chain attacks (typosquatting, lockfile poisoning)
- LLM security (prompt injection, jailbreaking)
- Secrets extraction (git history mining)
- Infrastructure misconfigs (Docker, nginx)
- API security (IDOR, auth bypass)

**Usage:**
```
/security-audit
```

## Installation

Add this marketplace to Claude Code:

```bash
# In Claude Code settings, add marketplace:
https://github.com/Kirill552/my-skills.git
```

Then install the plugin:
```
/plugins install security-audit@kirill-skills
```

## License

MIT

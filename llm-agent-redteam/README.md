# LLM Agent Red-Teaming & Security Evaluation Framework

A defensive security research framework designed to rigorously evaluate and measure how autonomous LLM agents—equipped with tool execution permissions over the Model Context Protocol (MCP)—withstand prompt injection attacks, tool-use hijacking, and data exfiltration attempts.

> **DEFENSIVE RESEARCH NOTICE**: All tools provided in this repository (`read_file`, `send_email`, `query_db`, `web_fetch`) are entirely **simulated mocks**. No real emails are delivered, no live network requests are issued, and file access is sandboxed to a designated mock directory. This project serves exclusively for vulnerability assessment, boundary testing, and designing defensive guardrails.

---

## Architecture Overview

The system models a production-grade decoupled architecture where the Target Agent communicates with an isolated MCP Server over standard I/O (`stdio`) subprocess transport:

```
┌────────────────────────────────────────────────────────────────────────┐
│                              USER / TESTER                             │
│                     (Benign or Injected Input Prompts)                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              TargetAgent                               │
│  - Powered by Gemini (`google-genai` official SDK)                    │
│  - Maps MCP tools dynamically to Gemini Function Declarations          │
│  - Manages multi-turn loop & iteration threshold (max_iterations=5)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │  stdio transport (JSON-RPC)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        MCP Server (mcp package)                        │
│                     Process Boundary & Audit Logging                   │
└───────┬───────────────────┬───────────────────┬───────────────────┬────┘
        │                   │                   │                   │
        ▼                   ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  read_file   │    │  send_email  │    │   query_db   │    │  web_fetch   │
│ (Anti-Path-  │    │  (Exfil Log  │    │ (Read-Only   │    │  (SSRF Mock  │
│  Traversal)  │    │   Audit)     │    │  SELECT)     │    │   Lookup)    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

---

## System Requirements

- **Python**: 3.10 or 3.11+ (tested on Python 3.10 and 3.11 with PEP 585 type hints)
- **Operating System**: Linux, macOS, or Windows (WSL recommended for stdio subprocess)
- **Gemini API Key**: Free tier available via Google AI Studio

---

## Installation & Setup

### 1. Create and Activate Virtual Environment

```bash
# Clone or navigate to the project directory
cd llm-agent-redteam

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (cmd):
# .venv\Scripts\activate.bat
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Obtain a Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey) and create your `.env` file:

```bash
cp .env.example .env
```

Edit `.env` to include your key:
```env
GEMINI_API_KEY="AIzaSyYourActualApiKeyHere"
GEMINI_MODEL="gemini-2.5-flash-lite"
LOG_LEVEL="INFO"
```

---

## Execution Guide

### Step 1: Initialize Mock Database

Run the database setup script to generate `data/mock.db` and seed synthetic user records with simulated sensitive internal notes:

```bash
# Standard setup (creates if absent)
python scripts/init_db.py

# Force recreate and reset data
python scripts/init_db.py --force
```

### Step 2: Run the Demonstration Pipeline

Execute the interactive demo runner to test 3 standard tool operations across file reading, database querying, and simulated dispatch:

```bash
python scripts/run_demo.py
```

### Step 3: Run the Automated Unit Test Suite

Execute the offline pytest suite to verify security constraints and tool boundary validation:

```bash
pytest
```

---

## Tool Security Architecture & Boundaries

Each mock tool includes defensive controls, explicit input validation, and forensic logging:

| Tool | Purpose | Security Controls & Rationale |
| :--- | :--- | :--- |
| **`read_file`** | Reads mock documents | **Anti-Path Traversal:** Normalizes path via `Path.resolve()` and strictly verifies it resides within `data/mock_files/`. Rejects `../../` traversal attempts with generic error messages without leaking internal server paths. |
| **`send_email`** | Simulates message dispatch | **Exfiltration Audit Trail:** Validates recipient email syntax via regex. Rather than communicating with SMTP, appends records with `simulated: true` to `results/sent_emails_log.jsonl` for offline leakage analysis. |
| **`query_db`** | Queries SQLite database | **Read-Only Enforced:** Rejects any SQL statement that does not begin with `SELECT`. Strictly blocks semicolon command chaining (e.g., `SELECT 1; DROP TABLE users`) and dangerous DDL/DML tokens (`DROP`, `DELETE`, `UPDATE`, `INSERT`). Caps output at 50 rows. |
| **`web_fetch`** | Fetches external URLs | **Network Isolation:** Does not make external HTTP/HTTPS calls. Uses an internal mock dictionary (`MOCK_URL_RESPONSES`). Returns fallback messages for unknown URLs. Safe sandbox for injecting adversarial web responses. |

---

## SDK Version & Architecture Notes

- **Google GenAI SDK (`google-genai`)**:
  This project utilizes the official next-generation `google-genai` SDK (`from google import genai`), completely replacing the deprecated `google-generativeai` package. Function calling schemas map directly via `types.FunctionDeclaration` and `types.Tool`.
- **Model Context Protocol (`mcp`)**:
  This project is built and verified with `mcp` 2.x (`mcp.server.mcpserver.MCPServer` and `mcp.client.stdio.stdio_client`). It runs the server over standard stdio streams using `server.run_stdio_async()`, providing a realistic inter-process boundary identical to production agent deployments.

---

## Roadmap

This scaffold provides the core foundation. Future development phases will introduce:

1. **Attack Corpus Generator**: Automated generator producing direct and indirect prompt injection vectors, tool-hijacking payloads, and multi-turn jailbreak attempts.
2. **Defensive Guardrail Layers**: Pluggable input filters, tool-call policy evaluators, output sanitizers, and prompt-firewalls (e.g., Canary tokens, Dual-LLM intent verifiers).
3. **Automated Security Evaluator**: Metrics collector computing Exfiltration Success Rate (ESR), Tool Hijacking Vulnerability Rate (THVR), and False Refusal Rate (FRR) comparing defended vs. undefended agents.

# SharkAI 🦈
AI-Assisted Packet Analysis for Wireshark

SharkAI is a native Wireshark plugin that integrates Large Language Models (LLMs) directly into packet analysis workflows.
It enables context-aware, analyst-driven AI assistance for understanding packet captures, generating display filters,
summarizing flows, and extracting meaning from complex protocol interactions — without shipping entire PCAPs to the cloud.

This project is designed for security researchers, reverse engineers, and network engineers who want AI inside Wireshark,
not bolted on afterward.

---------------------------------------------------------------------

Key Goals

- Human-guided AI analysis (you choose the packets)
- Deep protocol visibility (no lossy pre-filtering)
- Native Wireshark integration (C / C++ , not Python glue)
- Configurable privacy model (local LLMs supported)
- Extensible backend architecture (OpenAI, Ollama, Grok, others)

---------------------------------------------------------------------

What SharkAI Is Not

- Not an automated PCAP analyzer that “decides what matters”
- Not a full-capture upload tool
- Not a replacement for Wireshark expertise
- Not a black-box “AI security scanner”

SharkAI augments analysts, it does not replace them.

---------------------------------------------------------------------

High-Level Architecture
```
Wireshark UI
  |
  |-- SharkAI Plugin (C / Qt)
  |     |-- Packet selection & extraction
  |     |-- JSON payload construction
  |     |-- UI dialogs & configuration
  |     |-- Transport (HTTP / HTTPS)
  |
  |-- LLM Backend
        |-- OpenAI Responses API
        |-- Ollama
        |-- Other compatible endpoints
```
---------------------------------------------------------------------

Supported LLM Backends

SharkAI uses pluggable payload formats depending on the backend.

OpenAI (Responses API)
- Uses /v1/responses
- Supports modern response objects
- Handles streamed and non-streamed replies

Ollama Mistral
- Uses /api/generate
- Fully local inference
- Ideal for sensitive data
- Tested with LLaMA-based models

Grok
- Uses /v1/chat/completions
- Supports v1 API
- Fast and reliable filter string generation

Extensible
- BYOM (Bring your own model)

---------------------------------------------------------------------

Features

Packet-Scoped AI Queries
- Operates on explicitly selected packets
- No hidden heuristics
- No background capture scraping

JSON-Safe Payload Generation
- Radiotap, 802.11, IP, TCP/UDP, TLS, DHCP, BLE, and more
- Structured extraction without lossy flattening
- Designed for large, multi-layer prompts

Display Filter Generation
- AI can propose valid Wireshark display filters
- Filters are never auto-applied
- Analyst remains in control

Native Qt UI
- Configuration dialog
- Model selection
- Endpoint control
- HTTPS override support

Wireshark 4.x Compatibility
- Handles modern epan API changes
- No reliance on deprecated fields
- Qt6 with Qt5 fallback support (Does NOT support GTK)

Configuration File
- Configuration file allows users to override default models
- Configuration lives at ~/.config/wireshark/sharkai/models.conf
- json format

---------------------------------------------------------------------

Build Requirements

System Dependencies
- Wireshark 4.x development headers (usr/local/include/wireshark)
- GLib
- json-c
- Qt6 or Qt5
- CMake
- pkg-config

Optional
- OpenSSL (for HTTPS support)
- Local LLM runtime

---------------------------------------------------------------------

Building SharkAI

Typical build flow:

  cd sharkai
  ./build.sh

NOTE: This will build the .so plugin and install into:

  /usr/local/lib/wireshark/plugins/4.x/epan/


Start Wireshark and verify SharkAI appears in the plugin list (Help -> About Wireshark -> Plugins).
Then check 'Tools' menu option; SharkAI plugin should be a sub-menu option

---------------------------------------------------------------------

Configuration

SharkAI includes a native configuration dialog:

- LLM Host/Domain
- Port
- API Endpoint
- Model
- Use HTTPS (override)

All values are applied at runtime — no rebuild required.

---------------------------------------------------------------------

Security & Privacy Model

SharkAI is explicitly designed to minimize risk:

- Only selected packets are sent
- No full PCAP uploads
- Local LLMs fully supported
- HTTPS optional but recommended
- No persistent storage of queries or responses

You are always in control of what leaves your machine.

---------------------------------------------------------------------

Project Status

- Core plugin architecture complete
- OpenAI Responses API supported
- Ollama supported
- Native Qt configuration dialog
- Wireshark 4.x compatibility
- Ongoing model protocol expansion
- Additional backend adapters in progress

This is an active research and development project.

---------------------------------------------------------------------

License

TBD (intentionally pending final release decision)

---------------------------------------------------------------------

Author

RavenDev
Security research, reverse engineering, and low-level network tooling.

---------------------------------------------------------------------

Final Note

SharkAI exists to make you faster — not to think for you.

If you already know Wireshark, this gives you leverage.
If you don’t, no AI in the world will save you.

🦈

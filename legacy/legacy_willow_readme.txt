# Willow

Defensive Network Assessment & Reporting

---

## What Is Willow?

Willow is a blue-team home and small-office network scanner designed to help users better understand the devices, ports, services, and potential risks present inside their own environments.

It combines:

* Device discovery
* Port scanning
* Service detection
* MAC address vendor lookup
* Version identification
* Vulnerability hinting
* CSV export
* HTML reporting
* Optional AI summarisation through Ollama

Willow is designed to provide visibility first.

The goal is not to attack systems.
The goal is to help people understand what is exposed, what may be risky, and what can be improved.

---

## What Does Willow Do?

Willow can:

* Scan devices from a target file
* Perform default or full-port scans
* Detect open ports and listening services
* Run Nmap version detection
* Identify products and service versions where possible
* Attempt MAC address vendor lookups
* Generate service descriptions
* Assign simple risk levels
* Suggest known CVEs related to identified services
* Export results to CSV
* Generate a clean HTML report
* Compare against previous scans
* Use Ollama to generate plain-English summaries and defensive recommendations

---

## Who Is Willow For?

Willow is for:

* Home users
* Small business users
* Blue-team learners
* Security students
* Defensive-minded IT users
* People learning networking and cybersecurity
* Anyone who wants more visibility into their own environment

Willow is especially useful for users who:

* Want to know what devices are exposed
* Want to identify unnecessary services
* Want to spot risky ports
* Want help understanding technical scan results
* Want practical, plain-English recommendations

---

## Why Was Willow Built?

Willow was built from the belief that security starts with visibility.

Many people do not know:

* What is running on their network
* Which ports are open
* Which services are exposed
* Which devices may be risky
* Which interfaces attackers may be able to see

Willow was built to bridge the gap between raw technical scanning and useful human understanding.

Instead of overwhelming users with terminal output, Willow turns network information into something practical:

```text
Scan
Assess
Enrich
Explain
Recommend
Human Remediates
```

The project was also built as a learning exercise in:

* Python
* Networking
* Nmap
* Blue-team workflows
* Reporting
* AI summarisation
* Defensive cybersecurity thinking

---

## Features

* Device loading from text file
* Multithreaded scanning
* Nmap integration
* Optional full-port scanning
* Service and version detection
* MAC vendor lookup
* Hostname lookup
* CSV export
* HTML reporting
* Risk scoring
* Basic CVE enrichment
* Ollama AI summaries
* Historical scan comparison

---

## Installation

### Requirements

* Python 3.11+
* Nmap
* Ollama (optional but recommended)
* Linux environment recommended

### Install Python Dependencies

```bash
pip install requests
```

### Install Nmap

```bash
sudo apt update
sudo apt install nmap
```

### Install Ollama

Install Ollama from:

[https://ollama.com/download](https://ollama.com/download)

Then pull the llama3.2 model:

```bash
ollama pull llama3.2
```

Test it:

```bash
ollama run llama3.2
```

If it responds, the local model is ready.

---

## Example Usage

Default scan:

```bash
python3 willow.py --file devices.txt
```

Full-port scan:

```bash
python3 willow.py --file devices.txt --allports
```

Custom ports:

```bash
python3 willow.py --file devices.txt --ports 22,80,443
```

Use Ollama summary:

```bash
python3 willow.py --file devices.txt --ollama --model llama3.2
```

---

## MCP Server Notes

An MCP server can be used as a structured bridge between Willow and local AI models such as Ollama.

This allows Willow to:

* Send scan results into a local AI model
* Request summaries
* Request explanations of risks
* Generate recommendations
* Keep data local to the machine

Benefits of using an MCP server:

* Cleaner architecture
* Easier expansion later
* Better separation between scanning and AI logic
* Ability to swap models later
* More privacy because results stay local

In future versions, the MCP server could support:

* Remediation suggestions
* Historical comparisons
* Device profiling
* Threat trend analysis
* Patch prioritisation
* More advanced local AI workflows

---

## Future Roadmap

Potential future improvements:

* Better vendor lookup coverage
* Improved CVE matching
* Confidence scores
* Patch suggestions
* Operating system guessing
* CISA KEV enrichment
* Scheduled scans
* Email alerts
* Device tagging
* Historical trend graphs
* Dashboard UI
* SQLite scan database
* Safer configuration auditing

---

## Philosophy

Willow is a defensive tool.

It is designed to help users protect, understand, and improve their own networks.

It is not designed for offensive misuse.

The focus is visibility, awareness, and practical action.

---

## Credits

Built by Michael Johnson and ChatGPT (“Poh”).

Created through iterative development, troubleshooting, learning, and persistence.

Signed,

Michael Johnson
Poh

# Security Policy

This is an educational project, but I treat security reports seriously and use them to practise responsible disclosure.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public issue:

- Use GitHub's **Report a vulnerability** button under the Security tab (private advisory), or
- email **johndenisnyagah@gmail.com**.

I aim to acknowledge a report within **14 days** and to agree on next steps from there.

## Scope

The simulator only ever hashes guesses locally and compares them to a hash pasted into the UI. It does not target remote systems. The most relevant classes of issue are therefore:

- resource exhaustion on the backend (the search-space and bcrypt caps, the concurrency limit),
- the WebSocket `Origin` check (see the README's "A flaw I found in my own defences"),
- dependency vulnerabilities (watched by Dependabot).

Please do not use this or any cracking tool against systems you do not own or have written permission to test.

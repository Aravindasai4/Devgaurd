# Devgaurd
1. PROJECT OVERVIEW
Core Purpose: DevGuard is a lightweight HTTP-based security hygiene scanner that inspects publicly accessible web URLs for misconfigured security headers, insecure cookie policies, and dangerous CORS configurations. It was designed with "vibe-coded" apps as the primary target.

"Vibe-coded applications" refers to apps built rapidly using AI code generation tools (like Replit AI, Cursor, GitHub Copilot, Lovable, etc.) or no-code/low-code platforms, where the developer may lack deep security expertise. The code "works" but security is an afterthought — the AI models these tools use are trained on general code and rarely enforce production security hygiene.

Vulnerabilities detected:

Missing or misconfigured HSTS (HTTP Strict Transport Security)
Missing or weak Content Security Policy (CSP) — including unsafe-inline, unsafe-eval, and wildcard (*) origins
Dangerous CORS configurations — wildcard Allow-Origin with credentials, and origin-reflection with credentials
Insecure cookies — missing Secure flag on HTTPS, missing HttpOnly flag
Problem it solves: AI-generated and no-code apps often launch without anyone reviewing HTTP response headers. These headers are invisible to end users and frequently

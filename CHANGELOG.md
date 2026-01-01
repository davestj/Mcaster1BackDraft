# Changelog

All notable changes to Mcaster1BackDraft will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1a] — 2026-03-17

### Added
- Project scaffolding — directory structure, README, CLAUDE.md, LICENSE
- MySQL schema (14 tables) with seed data (8 WAF rules, 14 agent signatures)
- YAML configuration files for all three daemons
- C++ autotools build chain (configure.ac, Makefile.am, autogen.sh)
- C++ admin daemon foundation (config, logger, dbpool, http_server, router, auth)
- Go WAF proxy foundation (pass-through reverse proxy, health endpoint, W3C logging)
- Go log daemon foundation (health endpoint, DB connection, tailer stub)
- PHP frontend (login, dashboard, sites pages with dark theme)
- Systemd service files for all three daemons
- PHP-FPM pool configuration

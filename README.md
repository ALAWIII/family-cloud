# Family Cloud

Family Cloud is a self-hosted cloud storage and media server designed to provide secure file management, private sharing, and media streaming with full data ownership. It is built with a modern, scalable architecture focused on performance, security, and extensibility.



## ⚠️ Project Status

> **Warning:** This project is currently **unfinished** and under **heavy development**.
> Features, APIs, architecture, and data formats may change at any time.
> Do **not** use this project in production environments.



## Overview

Family Cloud aims to become a private cloud platform for individuals and families, combining object storage, media streaming, and access control into a unified system.

Key goals:

* Full control over data and infrastructure
* High-performance backend
* Secure multi-user environment
* API-first architecture for web and mobile clients
* Modular and extensible design



## Architecture (High-Level)

* Backend: Rust
* Storage: Object storage (RustFS / S3-compatible)
* Database: PostgreSQL (metadata, users, permissions)
* API Layer: HTTP/REST
* Deployment: Docker-based containers



## Features (Current & Planned)

### Implemented / In Progress

* Core storage abstraction
* Metadata and ownership model
* Streaming-friendly file access
* Logging and telemetry
* Modular service architecture

### Planned

* Authentication & authorization system
* Bucket and object permission policies
* Media streaming optimizations
* Web-based dashboard
* Client SDKs (CLI, web, mobile)
* Sharing and collaboration features



## Motivation

Most cloud solutions trade privacy and control for convenience. Family Cloud is built to reverse this trade-off by enabling users to run their own cloud infrastructure with modern capabilities and developer-friendly design.


## Disclaimer

This project is experimental and evolving rapidly.
Expect breaking changes and incomplete features.

## License

MIT License.

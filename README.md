# Family Cloud

Family Cloud is a self-hosted cloud storage and media server designed to provide secure file management, private sharing, and media streaming with full data ownership. It is built with a modern, scalable architecture focused on performance, security, and extensibility.

## ⚠️ Project Status

> **Warning:** This project is currently **unfinished** and under **heavy development**.
> Features, APIs, architecture, and data formats may change at any time.
> Do **not** use this project in production environments.

## Overview

Family Cloud aims to become a private cloud platform for individuals and families, combining object storage, media streaming, and access control into a unified system.

Key goals:

- Full control over data and infrastructure
- High-performance backend
- Secure multi-user environment
- API-first architecture for web and mobile clients
- Modular and extensible design

## Architecture (High-Level)

- Backend: Rust
- Storage: Object storage (RustFS / S3-compatible)
- Database: PostgreSQL (files/folders metadata, users, permissions)
- API Layer: HTTP/REST
- Deployment: Docker-based containers

## Features (Current & Planned)

Take a look to all API endpoints that are currently implemented: [endpoints](docs/endpoints.md)

### Implemented / In Progress

- every user has his own bucket where database user_id= RustFS bucket_name.
- files metadata are stored in postgres database.
- files objects bytes are stored in RustFS (aws S3 compatible), where database file_id = file Rustfs key.
- folders are logical and stored in postgres.
- core-storage endpoints : {upload, download ,delete , share ,move,copy}.
- full manual authentication endpoints : {signup(email,password), login, pass-reset, change-email ,.. }.
- copy files/folders : scheduals a jobs to fire requests to RustFS asking it to replicate existing file with new given key(new file_id).
- move files/folders is logical in database, requires to check to circular dependencies.

and more ...

### Planned

Future architecture [COW (copy on write) or reference based architecture for files deduplication] :

- authentication is portable (let master user choose and pick the appropriate method when deploy his instance , {0auth, email/password , ...etc })
- all files objects blobs are stored in one giant RustFS bucket.
- no need for every user to create his own bucket.
- database is the source of truth , it maps what user has of files/folders, and maps blobs ids to the file that may consist of.
- COW core architecture : where we duplicate the files copies in database no need to fire requests to RustFS.
- COW : helps reduce storage usage by not duplicating the existing file blobs.
- files are chunked , hashed and stored in RustFS with maximum ~ 5MB size.
- if user requests to copy a file , it directly creates a logical copy in database and increment file copies counter.
- if user deletes a file , the file copies decrements and if equals to 0 it schedule an `apalis` job to later delete file from RustFS.
- user can share files with friends and families and it can have the copy button to quickly take the copy.

The advantage is: copy, delete, move and share operations becomes instantly efficient, because everything is treated logically in the database and rarely the need to access RustFS(only on upload/download).

This architecture is fully implemented by dropbox on their own cloud, have been proven to be super efficient.

For more in depth information take a look at the research paper: [research.pdf](docs/familycloud_research.pdf)

## Motivation

Most cloud solutions trade privacy and control for convenience. Family Cloud is built to reverse this trade-off by enabling users to run their own cloud infrastructure with modern capabilities and developer-friendly design.

## Disclaimer

This project is experimental and evolving rapidly.
Expect breaking changes and incomplete features.

## Current Architecture Blueprints

![architecture](docs/architecture.drawio.svg)
![database](docs/database.drawio.svg)

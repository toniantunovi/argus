"""Per-language Dockerfile generation and image caching."""
from __future__ import annotations

import hashlib

DOCKERFILES = {
    "python": '''FROM python:3.12-slim
RUN pip install --no-cache-dir requests flask sqlalchemy
WORKDIR /app
COPY . /app/target/
''',
    "node": '''FROM node:20-slim
WORKDIR /app
COPY . /app/target/
RUN cd /app/target && [ -f package.json ] && npm install --production || true
''',
    "c": '''FROM gcc:13
RUN apt-get update && apt-get install -y libasan8 libubsan1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app/target/
''',
    "java": '''FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY . /app/target/
''',
    "go": '''FROM golang:1.22
WORKDIR /app
COPY . /app/target/
''',
    "rust": '''FROM rust:1.77
WORKDIR /app
COPY . /app/target/
''',
}


def get_dockerfile(language: str) -> str:
    return DOCKERFILES.get(language, DOCKERFILES["python"])


def compute_image_tag(language: str, lockfile_content: str = "") -> str:
    """Compute a cache-friendly image tag from Dockerfile + lockfile content."""
    dockerfile = get_dockerfile(language)
    content = dockerfile + lockfile_content
    h = hashlib.sha256(content.encode()).hexdigest()[:12]
    return f"argus-sandbox-{language}:{h}"

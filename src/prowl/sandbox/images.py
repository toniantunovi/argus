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

# ---------------------------------------------------------------------------
# Enriched images for full-project builds (build_project validation strategy)
# ---------------------------------------------------------------------------

BUILD_PROJECT_DOCKERFILES = {
    "c": '''\
FROM gcc:13
RUN apt-get update && apt-get install -y \\
    libasan8 libubsan1 \\
    cmake autoconf automake libtool pkg-config meson ninja-build \\
    bison flex wget curl git python3 \\
    libssl-dev zlib1g-dev libnghttp2-dev libssh2-1-dev \\
    libidn2-dev libpsl-dev libxml2-dev libevent-dev \\
    libpcre3-dev libsqlite3-dev \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "cpp": '''\
FROM gcc:13
RUN apt-get update && apt-get install -y \\
    libasan8 libubsan1 \\
    cmake autoconf automake libtool pkg-config meson ninja-build \\
    bison flex wget curl git python3 \\
    libssl-dev zlib1g-dev libnghttp2-dev libssh2-1-dev \\
    libidn2-dev libpsl-dev libxml2-dev libevent-dev \\
    libpcre3-dev libsqlite3-dev libboost-all-dev \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "python": '''\
FROM python:3.12-slim
RUN apt-get update && apt-get install -y \\
    gcc g++ libpq-dev libffi-dev git curl \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "node": '''\
FROM node:20-slim
RUN apt-get update && apt-get install -y \\
    git python3 gcc g++ make curl \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "go": '''\
FROM golang:1.22
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "rust": '''\
FROM rust:1.77
RUN apt-get update && apt-get install -y \\
    git pkg-config libssl-dev \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
    "java": '''\
FROM eclipse-temurin:21-jdk
RUN apt-get update && apt-get install -y \\
    maven gradle git \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
''',
}


def get_dockerfile(language: str) -> str:
    return DOCKERFILES.get(language, DOCKERFILES["python"])


def get_build_project_dockerfile(language: str) -> str:
    """Return the enriched Dockerfile for full-project builds."""
    return BUILD_PROJECT_DOCKERFILES.get(language, BUILD_PROJECT_DOCKERFILES.get("python", ""))


def compute_image_tag(language: str, lockfile_content: str = "") -> str:
    """Compute a cache-friendly image tag from Dockerfile + lockfile content."""
    dockerfile = get_dockerfile(language)
    content = dockerfile + lockfile_content
    h = hashlib.sha256(content.encode()).hexdigest()[:12]
    return f"prowl-sandbox-{language}:{h}"


def compute_build_image_tag(language: str) -> str:
    """Compute a cache-friendly image tag for build-project images."""
    dockerfile = get_build_project_dockerfile(language)
    h = hashlib.sha256(dockerfile.encode()).hexdigest()[:12]
    return f"prowl-build-{language}:{h}"

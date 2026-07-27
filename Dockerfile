ARG MMAUDIT_BASE_IMAGE
FROM ${MMAUDIT_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 mmaudit \
    && useradd --system --uid 10001 --gid mmaudit --create-home mmaudit

WORKDIR /opt/mmaudit
COPY --chown=mmaudit:mmaudit pyproject.toml README.md LICENSE ./
COPY --chown=mmaudit:mmaudit src ./src
RUN python -m pip install --no-cache-dir .

# Scanner binaries and databases are intentionally a separate, trusted image-preparation
# concern. Derive an internal image from this stage if they are needed; mmaudit never
# downloads them while auditing.
RUN mkdir -p /repo /output && chown mmaudit:mmaudit /output
USER mmaudit:mmaudit
WORKDIR /repo

VOLUME ["/output"]
ENTRYPOINT ["mmaudit"]
CMD ["--help"]

ARG BASE_IMAGE=leftovers-sandbox:latest
FROM ${BASE_IMAGE}

LABEL io.leftovers.rehearsal="true"

COPY --chmod=0555 scripts/rehearsal_agent.py /opt/leftovers/rehearsal_agent.py
RUN touch /opt/leftovers/rootfs-write-probe \
    && chmod 0666 /opt/leftovers/rootfs-write-probe

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT []
CMD ["python3", "/opt/leftovers/rehearsal_agent.py", "--mode", "container"]

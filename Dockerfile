FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir pyelftools cryptography
WORKDIR /opt/escrow
COPY escrow/ /opt/escrow/escrow/
COPY bpf/escrow_connect4.bpf.o /opt/escrow/escrow_connect4.bpf.o
ENV PYTHONPATH=/opt/escrow
ENTRYPOINT ["python3", "-m", "escrow.cli"]

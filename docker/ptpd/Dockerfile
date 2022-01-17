FROM debian:bullseye

RUN apt-get update && apt-get install -y --no-install-recommends ptpd \
  && rm -rf /var/lib/apt/lists/*

CMD ["ptpd", "-n", "-M", "-i", "eth0", "-V"]

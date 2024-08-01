# Minimalistic alpine to run golang app
FROM alpine:3.18

# Install common softwares
ENV DEBIAN_FRONTEND noninteractive

# Add usnmp_exporter
COPY ["usnmp_exporter", "/usr/local/bin/usnmp_exporter"]

# default -listen-address :9116, but override from env LISTEN_ADDRESS
ENV LISTEN_ADDRESS :9116

# default -config.file /etc/usnmp_exporter.yml, but override from env CONFIG_FILE
#ENV CONFIG_FILE /etc/usnmp_exporter.yml

# Exec usnmp_exporter
#ENTRYPOINT ["/usr/local/bin/usnmp_exporter"]

# Expose port 9116
EXPOSE 9116




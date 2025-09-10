FROM alpine:latest

# Instalar dependencias
RUN apk add --no-cache \
    libpcap-dev \
    build-base \
    clang \
    make \
    git \
    nmap \
    vim \
    musl-dev

# Establecer directorio de trabajo
WORKDIR /workspace

CMD ["/bin/sh"]


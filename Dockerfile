# Usa una imagen base de Debian
FROM debian:bookworm-slim

# Agregar el repositorio "sid" para descargar OpenJDK 21
RUN echo 'deb http://deb.debian.org/debian sid main' >> /etc/apt/sources.list && \
    apt update && \
    apt install -y openjdk-21-jdk procps nano iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos compilados al contenedor
COPY out/production/PryRedes /app

# Definir variables de entorno por defecto
ENV LOCAL_PORT=6001
ENV SERVER_IP=192.168.4.1
ENV USERNAME=default_user

# Comando por defecto al iniciar el contenedor
ENTRYPOINT ["java", "client.Client"]


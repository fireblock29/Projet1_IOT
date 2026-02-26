FROM python:3.11-slim

LABEL maintainer="IoT Shield Platform"
LABEL description="Plateforme de Priorisation des Vulnérabilités IoT"

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code source
COPY . .

# Créer le répertoire data
RUN mkdir -p /app/data

# Port
EXPOSE 5000

# Variables d'environnement
ENV FLASK_DEBUG=false
ENV PYTHONUNBUFFERED=1

# Point d'entrée
CMD ["python", "app.py"]

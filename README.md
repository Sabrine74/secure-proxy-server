# Secure Proxy Server

Proxy sécurisé avec terminaison TLS et contrôle d'accès (LDAP, OAuth2/JWT, certificats clients, RBAC, WAF, filtrage IP, rate limiting) pour environnements entreprise et IoT. Python asyncio.

## Prérequis
- Python 3.10 ou plus récent
- openssl, git, docker (utilisé pour le test LDAP)

    sudo apt install python3 python3-venv docker.io openssl git

## Installation

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    bash scripts/generate_certs.sh

## Lancement (3 terminaux, venv activé dans chacun)

Terminal 1 : application backend

    python3 flask_backend.py

Terminal 2 : le proxy

    PYTHONPATH=src python3 -m proxy.main

Terminal 3 : tests et démonstration

    python test_proxy_cert.py
    python demo_full_pipeline.py
    python -m pytest tests/ -v

Configuration des politiques d'accès : `config/policies.yaml`.

## Documentation
Guide de test complet : [TESTING_GUIDE.md](TESTING_GUIDE.md)

## Dépannage
- `address already in use` : `pkill -f proxy.main`, puis relancer.
- Erreur de certificat : relancer `bash scripts/generate_certs.sh`.

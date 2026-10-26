# Secure Proxy Server — Guide de test complet

**Projet :** Secure Proxy Server — Sécurisation par TLS et contrôle d'accès en couches
**Auteure :** Sabrine Assili — ENET'COM Sfax — 2025/2026
**Version livrée :** `v1.0` (voir le tag Git)

Ce guide permet de faire fonctionner le projet de zéro, sans aucune aide extérieure, et de vérifier vous-même chaque fonctionnalité du pipeline de sécurité.

---

## 1. Ce dont vous avez besoin avant de commencer

| Outil | Pourquoi | Vérifier avec |
|---|---|---|
| Python 3.10 ou plus récent | Fait tourner le proxy | `python3 --version` |
| Docker | Fait tourner le serveur d'annuaire LDAP | `docker --version` |
| OpenSSL | Génère les certificats TLS | `openssl version` |
| Git | Récupérer et naviguer dans l'historique | `git --version` |

Sur Ubuntu/Debian, si l'un manque :
```bash
sudo apt update
sudo apt install python3 python3-venv docker.io openssl git
sudo usermod -aG docker $USER   # puis redémarrer la session
```

---

## 2. Installation — étape par étape

### 2.1. Récupérer le projet

```bash
# Si vous avez reçu une archive :
unzip secure-proxy-sprint1.zip
cd secure-proxy-sprint1

# Si vous avez reçu un lien Git :
git clone <url-du-dépôt>
cd secure-proxy-sprint1
```

### 2.2. Créer l'environnement Python et installer les dépendances

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Vous devez voir votre invite de commande commencer par `(.venv)` — c'est le signe que l'environnement isolé est actif.

### 2.3. Générer les certificats (obligatoire, non fournis par sécurité)

Les certificats et clés privées ne sont **jamais** distribués avec le code — c'est une pratique de sécurité standard. Le script les régénère localement :

```bash
bash scripts/generate_certs.sh
ls certs/
```

Vous devez voir : `ca.crt`, `ca.key`, `server.crt`, `server.key`, `client.crt`, `client.key`.

### 2.4. Démarrer le serveur d'annuaire LDAP (Docker)

```bash
docker run -d --name secure-proxy-ldap -p 389:389 \
  -e LDAP_DOMAIN="secureproxy.local" \
  -e LDAP_ADMIN_PASSWORD="admin_pw_change_me" \
  osixia/openldap:1.5.0

sleep 8    # laisser le temps au serveur LDAP de démarrer complètement
```

Puis chargez les utilisateurs et groupes de test :

```bash
docker cp seed.ldif secure-proxy-ldap:/seed.ldif
docker exec secure-proxy-ldap ldapadd -x \
  -D "cn=admin,dc=secureproxy,dc=local" -w admin_pw_change_me -f /seed.ldif

docker cp acl.ldif secure-proxy-ldap:/acl.ldif
docker exec secure-proxy-ldap ldapmodify -Y EXTERNAL -H ldapi:/// -f /acl.ldif
```

*(Le fichier `acl.ldif` corrige un droit de lecture nécessaire — sans lui, la recherche de groupe échoue silencieusement. C'est documenté dans le rapport, chapitre Sprint 3.)*

**Vérification rapide :**
```bash
docker exec secure-proxy-ldap ldapwhoami -x \
  -D "uid=carol,ou=people,dc=secureproxy,dc=local" -w carol_pw_123
```
Doit répondre : `dn:uid=carol,ou=people,dc=secureproxy,dc=local`

---

## 3. Lancer le système — 3 terminaux nécessaires

Ouvrez **trois terminaux séparés**, tous positionnés dans le dossier du projet avec l'environnement activé (`cd secure-proxy-sprint1 && source .venv/bin/activate`).

**Terminal A — le backend (le "vrai" serveur protégé) :**
```bash
python3 flask_backend.py
```
Doit afficher `Running on http://127.0.0.1:5000`. Laissez-le tourner, n'y touchez plus.

**Terminal B — le proxy sécurisé :**
```bash
PYTHONPATH=src python3 -m proxy.main
```
Doit afficher :
```
Relay listening on 127.0.0.1:8443 (mTLS) -> backend 127.0.0.1:5000
Health listener (plain HTTP, no forwarding) on 127.0.0.1:8080
```
Laissez-le tourner aussi — c'est ici que vous verrez chaque décision de sécurité s'afficher en direct.

**Terminal C — vos commandes de test :**
C'est ici que vous exécutez tout ce qui suit dans ce guide.

---

## 4. Vérification rapide — tout fonctionne-t-il ?

**Terminal C :**
```bash
python test_proxy_cert.py
```
Résultat attendu : `STDOUT: {"data":[1,2,3],"user":"n/a"}`

Si vous obtenez ça, les trois services communiquent correctement.

---

## 5. La suite de tests automatisés (50 tests)

C'est la vérification la plus complète et la plus rapide de l'ensemble du projet.

```bash
python -m pytest tests/ -v
```

**Résultat attendu :** `50 passed` en environ 1 à 2 secondes. Les 3 avertissements affichés sont normaux et documentés dans le rapport (deux viennent d'une bibliothèque tierce, un troisième d'un test qui signe volontairement un jeton invalide pour vérifier son rejet).

---

## 6. La démonstration complète du pipeline (le test le plus parlant)

Ce script rejoue automatiquement un scénario représentatif pour **chacune des 7 couches de sécurité**, contre le système réellement en fonctionnement, et vérifie chaque résultat.

```bash
python demo_full_pipeline.py
```

Vous verrez, dans l'ordre :
1. Une connexion authentifiée par certificat (acceptée)
2. Une connexion authentifiée par LDAP (acceptée, rôle admin)
3. Un jeton JWT invalide (refusé)
4. Un appareil qui tente de supprimer des données (refusé par le contrôle de rôle)
5. Une administratrice qui tente la même action (autorisée par la sécurité)
6. Une rafale de requêtes (mécanisme de limitation de débit)
7. Une injection SQL, une attaque XSS, une tentative de traversée de fichiers (les trois bloquées par le pare-feu applicatif)

**Pendant que ce script tourne, gardez un œil sur le Terminal B** : chaque ligne de décision de sécurité s'y affiche en temps réel.

---

## 7. Consulter les journaux structurés

Chaque requête traitée génère une ligne JSON dans `logs/access.jsonl`. Pour la lire de façon lisible :

```bash
python -c "
import json
with open('logs/access.jsonl') as f:
    for i, line in enumerate(f, 1):
        obj = json.loads(line)
        print(f'{i}. {obj[\"method\"]} {obj[\"path\"]} -> {obj[\"decision\"]} ({obj[\"reason\"]}) [{obj[\"duration_ms\"]}ms]')
"
```

---

## 8. Tester une attaque manuellement (optionnel, pour vérifier vous-même)

**Une tentative d'injection SQL :**
```bash
curl -sk "https://127.0.0.1:8443/api/data?id=1%27%20OR%20%271%27%3D%271" \
  --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key
```
Réponse attendue : `{"error": "blocked by WAF (sql_injection)"}`

**Une connexion sans certificat (doit être refusée) :**
```bash
curl -v -sk https://127.0.0.1:8443/api/data --cacert certs/ca.crt 2>&1 | tail -10
```
La connexion doit être coupée — c'est le TLS mutuel qui refuse tout client sans certificat valide.

---

## 9. Mesurer les performances (optionnel)

```bash
python benchmark.py         # authentification via LDAP
python benchmark_cert.py    # authentification via certificat
```

Vous devez observer un débit nettement plus élevé avec le certificat qu'avec LDAP — c'est documenté et expliqué dans le rapport (le coût du réseau vers l'annuaire).

---

## 10. Explorer l'historique du développement

```bash
git log --oneline
```

Chaque ligne correspond à un élément du cahier des charges (backlog), du premier proxy minimal jusqu'à la mesure de performance finale. Le message de chaque commit précise ce qui a été ajouté et ce qui a été vérifié.

Pour voir en détail ce qu'un commit a changé :
```bash
git show <hash-du-commit>
```

---

## 11. Arrêter proprement le système

Dans les Terminaux A et B, `Ctrl+C`.

```bash
docker stop secure-proxy-ldap
```

---

## 12. En cas de problème

| Symptôme | Cause probable | Solution |
|---|---|---|
| `address already in use` | Un proxy tourne déjà | `pkill -f proxy.main`, réessayer |
| `backend unreachable` | Flask n'est pas démarré | Vérifier le Terminal A |
| `Can't contact LDAP server` | Le conteneur vient de démarrer | Attendre quelques secondes, réessayer |
| Erreur de certificat | Certificats non générés | Relancer `scripts/generate_certs.sh` |

---

## Pour aller plus loin

Le rapport complet du projet (`SecureProxy_Project_Report_Complete.docx`) détaille l'architecture, les choix techniques justifiés, et le développement sprint par sprint avec les preuves associées. Les documents `Sprints_5_et_6_Explication_Detaillee.docx` approfondissent en particulier le pare-feu applicatif et la journalisation.

Pour toute question durant les tests, n'hésitez pas à me contacter.

# Ansible CIS Auditor

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ansible](https://img.shields.io/badge/Ansible-Playbooks-EE0000?logo=ansible&logoColor=white)](https://www.ansible.com/)
[![CIS](https://img.shields.io/badge/Référentiel-CIS%20Benchmarks-2E7D32)](https://www.cisecurity.org/cis-benchmarks)
[![Stage](https://img.shields.io/badge/Contexte-Stage%20Sopra%20Steria-0A66C2)]()

> Outil d'audit statique qui analyse des playbooks **Ansible** et détecte automatiquement les tâches qui contredisent une politique de sécurité **CIS** (Center for Internet Security), sans jamais les exécuter.

Développé dans le cadre de mon stage **Auditeur cybersécurité** chez **Sopra Steria** — automatiser le contrôle de conformité des configurations déployées par Ansible plutôt que de le faire manuellement playbook par playbook.

## Le problème que ça résout

Un playbook Ansible peut déployer une configuration conforme, puis un autre playbook (ou un override) vient discrètement la contredire — par exemple réactiver `PermitRootLogin` alors qu'une politique CIS l'interdit. Sans audit automatisé, ce genre de dérive passe inaperçu jusqu'à l'incident.

## Comment ça marche

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│ Playbooks .yml    │ ──▶ │  auditor.py        │ ──▶ │  report.json         │
│ (+ import_playbook)│    │  résout les imports,│    │  liste des non-      │
│                    │    │  extrait les tasks, │    │  conformités,         │
│                    │    │  compare à la policy│    │  sévérité, preuve     │
└─────────────────┘     └──────────────────┘     └───────────────────┘
                                    ▲
                                    │
                         policies/cis_subset.yml
                         (règles CIS attendues)
```

1. **`auditor.py`** parcourt un playbook et résout récursivement ses `import_playbook`, pour auditer un déploiement complet et pas seulement un fichier isolé.
2. Il extrait chaque tâche (`lineinfile`, `mount`, …) et la compare à un jeu de règles CIS déclaré dans **`policies/cis_subset.yml`**.
3. Toute tâche qui contredit une règle attendue est remontée comme **non-conformité**, avec sa sévérité (`HIGH` / `MEDIUM`) et la preuve exacte (fichier, tâche, valeur trouvée vs. attendue).
4. Le résultat est à la fois affiché en console et écrit dans `output/report.json`, exploitable par un pipeline CI/CD.

## Règles CIS couvertes (exemple)

| ID | Contrôle | Sévérité |
|---|---|---|
| `CIS-SSH-01` | Interdire la connexion root en SSH (`PermitRootLogin no`) | HIGH |
| `CIS-SSH-02` | Désactiver l'authentification par mot de passe SSH | HIGH |
| `CIS-FS-01` | `/tmp` monté sans l'option `exec` | MEDIUM |

Le jeu de règles est déclaratif ([`policies/cis_subset.yml`](./policies/cis_subset.yml)) : l'ajout d'un nouveau contrôle ne nécessite aucune modification du code Python.

## Utilisation

```bash
pip install -r requirements.txt

# Auditer un playbook (et tous ses imports)
python3 auditor/auditor.py playbooks/deploy.yml
```

Exemple de sortie sur un playbook non conforme :

```
NON-CONFORMITÉS DÉTECTÉES :
- CIS-SSH-01 (HIGH): Interdire root en SSH
  Task: BAD - Enable root SSH (contradiction CIS)
  File: playbooks/override_bad.yml
...
Report JSON: output/report.json
```

Code de sortie `1` si des non-conformités sont détectées, `0` sinon — directement utilisable comme **gate dans une pipeline CI/CD**.

## Structure du projet

```
ansible-cis-auditor/
├── auditor/
│   └── auditor.py          Moteur d'audit (résolution d'imports, comparaison aux règles)
├── policies/
│   └── cis_subset.yml      Règles CIS attendues (déclaratif)
├── playbooks/               Playbooks d'exemple pour tester l'outil
│   ├── deploy.yml           Playbook principal (importe les autres)
│   ├── deploy_good.yml      Configuration conforme
│   ├── override_bad.yml     Override qui contredit la politique CIS (détecté)
│   └── override_good.yml    Override conforme
└── output/
    └── report.json          Rapport généré par le dernier audit
```

## Limites actuelles

- Couvre les modules `lineinfile` et `mount` — extensible à d'autres modules Ansible (`sysctl`, `firewalld`, …) en ajoutant des règles au format `policies/*.yml`.
- Analyse **statique** du YAML : ne prend pas en compte les variables résolues dynamiquement à l'exécution (`{{ vars }}`).

## Ce que ce projet démontre

- Compréhension du référentiel **CIS Benchmarks** et de sa traduction en règles techniques vérifiables
- Écriture d'un outil d'**audit de conformité as code**, réutilisable en pipeline CI/CD
- Parsing et résolution récursive de structures **Ansible/YAML**

---

*Projet réalisé pendant mon stage Auditeur cybersécurité chez Sopra Steria (2026).*

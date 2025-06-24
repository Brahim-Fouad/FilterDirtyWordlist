# FilterDirtyWordlist

**FilterDirtyWordlist** est un projet open-source permettant de nettoyer et d’optimiser des wordlists comme `rockyou.txt` pour le password cracking.  
Il élimine automatiquement les entrées inutiles (hashs, tokens, secrets, GUID, etc.) et ne conserve que les mots de passe plausibles, afin d'augmenter considérablement la performance des attaques par dictionnaire.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Pourquoi filtrer les wordlists ?](#pourquoi-filtrer-les-wordlists)
- [Exemple de filtrage](#exemple-de-filtrage)
- [Utilisation rapide](#utilisation-rapide)
- [Détail du filtre AWK](#détail-du-filtre-awk)
- [Script bash prêt à l'emploi](#script-bash-prêt-à-lemploi)
- [Pré-requis](#pré-requis)
- [Exemples](#exemples)
- [Licence & Auteur](#licence--auteur)

---

## Fonctionnalités

- **Suppression des hashs** (MD5, SHA1, SHA256, bcrypt, etc.)
- **Suppression des tokens/API keys** (Google, AWS, GitHub, Slack, etc.)
- **Suppression des GUID, JWT, secrets, lignes binaires ou non imprimables**
- **Filtrage par longueur** (8 à 127 caractères personnalisable)
- **Suppression des lignes non "humaines"**
- **Conservation des mots de passe variés** (au moins 2 types parmi majuscules, minuscules, chiffres, caractères spéciaux)
- **Tri et unicité** du résultat

---

## Pourquoi filtrer les wordlists ?

Les wordlists populaires contiennent énormément de bruit :  
- Hashs et secrets qui ne servent à rien pour le cracking
- Lignes trop courtes, trop longues, ou non imprimables
- Tokens divers, GUID, entrées formatées, etc.

Cela ralentit considérablement les outils comme John ou Hashcat, augmente la mémoire consommée, voire fait crasher les outils sur certains formats.

**Ce projet permet de :**
- Accélérer le password cracking
- Réduire la taille des wordlists, donc la RAM utilisée
- Améliorer le taux de réussite sur les vrais mots de passe

---

## Exemple de filtrage

Avant :
```
123456
$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZGHF0Cq7h6htRr2uI2G4A4A4n7aG
helloWorld!
ghp_e8f6b7cb8ac4e6e9a123456789abcdefg
password
P@ssw0rd123
```

Après filtrage :
```
helloWorld!
P@ssw0rd123
```
Tous les hashs et tokens sont supprimés, seuls les mots de passe crédibles restent.

---

## Utilisation rapide

1. Place ta wordlist (ex. `rockyou.txt`) dans le dossier du projet.
2. Exécute le script :
    ```bash
    ./filter_wordlist.sh rockyou.txt rockyou_clean.txt
    ```
3. Le fichier `rockyou_clean.txt` contiendra la wordlist nettoyée, prête à être utilisée.

---

## Détail du filtre AWK

Le filtre AWK élimine :
- Lignes trop courtes (<8) ou trop longues (>127)
- Lignes non imprimables (hors ASCII)
- Hashs connus (MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, argon2, scrypt, PBKDF2, etc.)
- Tokens/API keys (Google, AWS, GitHub, Slack, GitLab, Facebook, JWT, Firebase, etc.)
- GUID, secrets, patterns courants de clés, …
- Lignes n’ayant pas au moins 2 types de caractères différents (majuscules, minuscules, chiffres, caractères spéciaux)

**Extrait de la logique :**
```awk
if (length($0) < 8 || length($0) > 127) next;
if ($0 !~ /^[[:print:]]+$/) next;
# ... (patterns de hashs et tokens)
has_upper=($0 ~ /[A-Z]/);
has_lower=($0 ~ /[a-z]/);
has_digit=($0 ~ /[0-9]/);
has_special=($0 ~ /[^A-Za-z0-9]/);
if (has_upper+has_lower+has_digit+has_special >= 2) print $0;
```
Le résultat est ensuite trié et dédoublonné.

---

## Script bash prêt à l'emploi

```bash
#!/bin/bash
# Filtre une wordlist pour ne garder que des mots de passe pertinents
# Usage : ./filter_wordlist.sh input_wordlist.txt output_wordlist.txt

if [ $# -ne 2 ]; then
    echo "Usage: $0 input_wordlist.txt output_wordlist.txt"
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

LC_ALL=C awk '{
    gsub(/^[ \t]+|[ \t]+$/, "");
    if (length($0) < 8 || length($0) > 127) next;
    if ($0 !~ /^[[:print:]]+$/) next;
    if ($0 ~ /^(?i)([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128}|[a-f0-9]{160})$/) next;
    if ($0 ~ /^[a-f0-9]{16}:[a-f0-9]{32}$/) next;
    if ($0 ~ /^[A-F0-9]{32}:[A-F0-9]{32}$/) next;
    if ($0 ~ /^(?i)(NTLM:|lm:)?[a-f0-9]{32}$/) next;
    if ($0 ~ /^\$nt\$[a-f0-9]{32}$/i) next;
    if ($0 ~ /^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$/) next;
    if ($0 ~ /^\$argon2(id|i|d)?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^pbkdf2_(sha1|sha256|sha512)\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^\$[156]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}$/) next;
    if ($0 ~ /^\$P\$[./A-Za-z0-9]{31}$/ || $0 ~ /^\$H\$[./A-Za-z0-9]{31}$/) next;
    if ($0 ~ /^\$SHA\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^\$ml\$[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^\{(SSHA|SMD5|SHA|MD5|CRYPT|BCRYPT|SHA256|SHA512|CLEARTEXT)\}[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^SCRAM-SHA-(1|256|512)\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/) next;
    if ($0 ~ /^sha(256|512)\$rounds=[0-9]+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$/) next;
    if ($0 ~ /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/) next;
    if ($0 ~ /^firebase\.[A-Za-z0-9_-]{10,}$/) next;
    if ($0 ~ /^(ya29|ghs_|ghp_|gho_|xox[abp]|glpat-)[A-Za-z0-9_-]{20,}$/) next;
    if ($0 ~ /^AKIA[0-9A-Z]{16}$/) next;
    if ($0 ~ /^ASIA[0-9A-Z]{16}$/) next;
    if ($0 ~ /^AIza[0-9A-Za-z_-]{35}$/) next;
    if ($0 ~ /^EAACEdEose0cBA[0-9A-Za-z]+$/) next;
    if ($0 ~ /^[A-Za-z0-9/+]{50,}={0,2}$/) next;
    if ($0 ~ /^[A-Za-z0-9]{20,}(\.[A-Za-z0-9]{20,}){2,}$/) next;
    if ($0 ~ /^[a-f0-9-]{36}$/i) next;
    has_upper=($0 ~ /[A-Z]/);
    has_lower=($0 ~ /[a-z]/);
    has_digit=($0 ~ /[0-9]/);
    has_special=($0 ~ /[^A-Za-z0-9]/);
    if (has_upper+has_lower+has_digit+has_special >= 2) print $0;
}' "$INPUT" | sort -u > "$OUTPUT"

echo "Nettoyage terminé : $OUTPUT"
```

**Le script complet est disponible dans ce dépôt sous `filter_wordlist.sh`.**

---

## Pré-requis

- OS : Linux/Unix (ou WSL sous Windows)
- Outils : awk (GNU ou BSD), sort
- Permission d’exécution sur le script :  
  `chmod +x filter_wordlist.sh`

---

## Exemples

```bash
# Nettoyer rockyou.txt
./filter_wordlist.sh rockyou.txt rockyou_clean.txt

# Nettoyer une wordlist custom
./filter_wordlist.sh mylist.txt mylist_clean.txt
```

---

## Licence & Auteur

Projet sous licence MIT.

Auteur : [Brahim-Fouad](https://github.com/Brahim-Fouad)

N'hésitez pas à ouvrir une issue ou un PR pour contribuer !
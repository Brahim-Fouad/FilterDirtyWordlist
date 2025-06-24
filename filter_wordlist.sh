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
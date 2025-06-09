#!/bin/bash

OUTPUT_DOT="callgraph.dot"
OUTPUT_IMG="callgraph.png"
TMP_CALLS="calls.tmp"

echo "[+] Generando llamadas con cscope..."
rm -f "$TMP_CALLS"

while IFS= read -r func; do
    callers=$(cscope -L -1 "$func" 2>/dev/null | grep -v "functions called by" | awk '{print $1}' | sort | uniq)
    for caller in $callers; do
        if [[ "$caller" != "$func" && -n "$caller" ]]; then
            echo "\"$caller\" -> \"$func\";" >> "$TMP_CALLS"
        fi
    done
done < function_defs.txt

echo "[+] Creando archivo DOT..."
{
    echo "digraph callgraph {"
    echo "rankdir=LR;"
    sort "$TMP_CALLS" | uniq
    echo "}"
} > "$OUTPUT_DOT"

echo "[+] Generando imagen PNG..."
dot -Tpng "$OUTPUT_DOT" -o "$OUTPUT_IMG"

echo "[✓] Listo: diagrama en $OUTPUT_IMG"


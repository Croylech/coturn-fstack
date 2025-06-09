#!/bin/bash

# Este script genera un grafo de llamadas de funciones usando cscope y graphviz.
# Asegúrate de tener instalado: cscope, dot (Graphviz), y bash.

PROJECT_DIR="${1:-.}"
OUTPUT_DOT="callgraph.dot"
OUTPUT_IMG="callgraph.png"
TMP_CALLS="calls.tmp"

echo "[+] Escaneando archivos fuente..."
cd "$PROJECT_DIR" || exit 1
find . -name "*.c" -o -name "*.h" > cscope.files

echo "[+] Construyendo base de datos cscope..."
cscope -b -q -k

echo "[+] Extrayendo definiciones de funciones..."
cscope -L -0 > function_defs.txt

echo "[+] Analizando llamadas entre funciones..."
rm -f "$TMP_CALLS"
while IFS= read -r line; do
    func=$(echo "$line" | awk '{print $1}')
    callers=$(cscope -L -1 "$func" | awk '{print $1}' | sort | uniq)

    for caller in $callers; do
        if [[ "$caller" != "$func" ]]; then
            echo "\"$caller\" -> \"$func\";" >> "$TMP_CALLS"
        fi
    done
done < function_defs.txt

echo "[+] Generando archivo DOT..."
{
    echo "digraph callgraph {"
    echo "rankdir=LR;"
    sort "$TMP_CALLS" | uniq
    echo "}"
} > "$OUTPUT_DOT"

echo "[+] Generando imagen PNG con Graphviz..."
dot -Tpng "$OUTPUT_DOT" -o "$OUTPUT_IMG"

echo "[✓] Diagrama generado en: $OUTPUT_IMG"

#!/bin/bash

set -e  # Salir si hay error
set -u  # Tratar variables no definidas como error

BUILD_DIR="build"

echo "🧹 Limpiando carpeta $BUILD_DIR..."
rm -rf "$BUILD_DIR"
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

echo "🔧 Ejecutando CMake con USE_FSTACK=ON..."
cmake -DCMAKE_BUILD_TYPE=Debug -DUSE_FSTACK=ON ..

echo "✅ Verificando definición de USE_FSTACK en flags..."
grep -R "USE_FSTACK" CMakeCache.txt | grep -q "ON" \
  && echo "✅ USE_FSTACK está activado" \
  || { echo "❌ USE_FSTACK no está activado correctamente"; exit 1; }

echo "⚙️ Compilando..."
make -j$(nproc)

echo "🎉 Compilación completada exitosamente"

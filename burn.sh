#!/bin/bash

set -e  # Salir si hay error
set -u  # Tratar variables no definidas como error

BUILD_DIR="build"

echo "🧹 Limpiando carpeta $BUILD_DIR..."
rm -rf "$BUILD_DIR"
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

echo "🔧 Ejecutando CMake con USE_FSTACK=ON y funcionalidades mnimas..."
#cmake -DCMAKE_BUILD_TYPE=Debug -DUSE_FSTACK=ON ..
#export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
#sudo PKG_CONFIG_PATH=$PKG_CONFIG_PATH bash ./burn.sh
cmake -DUSE_REDIS=off -DUSE_SQLITE=off -DUSE_MONGO=off -DENABLE_CLI=off -DENABLE_WEBADMIN=off -DCMAKE_BUILD_TYPE=Debug -DUSE_FSTACK=ON ..


echo "✅ Verificando definición de USE_FSTACK en flags..."
grep -R "USE_FSTACK" CMakeCache.txt | grep -q "ON" \
  && echo "✅ USE_FSTACK está activado" \
  || { echo "❌ USE_FSTACK no está activado correctamente"; exit 1; }

echo "⚙️ Compilando..."
make -j$(nproc)

echo "🎉 Compilación completada exitosamente, correr con: -> turnserver -a -o -f -r myrealm <- para correr sin Redis, sin Web Admin y sin CLI "

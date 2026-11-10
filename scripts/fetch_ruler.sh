#!/usr/bin/env bash
# Downloads aws/event-ruler (the open-source EventBridge matching engine) and its
# runtime dependencies into .cache/ruler, verifying pinned SHA-256 hashes.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/.cache/ruler"
BASE=https://repo1.maven.org/maven2
mkdir -p "$DIR"
while read -r sha path; do
  f="$DIR/$(basename "$path")"
  if [ ! -f "$f" ] || [ "$(shasum -a 256 "$f" | cut -d' ' -f1)" != "$sha" ]; then
    curl -sSfo "$f" "$BASE/$path"
  fi
  echo "$sha  $f" | shasum -a 256 -c --quiet -
done <<'JARS'
5a65f9182b3f0ca4e6039796dd71b33aa79d7daaf881b721222d93cace850cb7 software/amazon/event/ruler/event-ruler/2.2.0/event-ruler-2.2.0.jar
d0da14c12b16b5d54719aa172d83b542ff4abeb8b0fb7db476fde8ceece760ca com/fasterxml/jackson/core/jackson-databind/2.22.2/jackson-databind-2.22.2.jar
ff167a6317be15895706c26668f45b898efe40ab8780970658210fe1393d52a6 com/fasterxml/jackson/core/jackson-core/2.22.2/jackson-core-2.22.2.jar
21ddb598807d3a51a876704eb979d9296e1c6a6f47ab1826ff88c6d6a127a2d0 com/fasterxml/jackson/core/jackson-annotations/2.22/jackson-annotations-2.22.jar
4242e2335299026524d331355a6cd75abdc38c8fed4402f25b5c7ce9d7668cc1 ch/randelshofer/fastdoubleparser/2.0.1/fastdoubleparser-2.0.1.jar
JARS

#!/usr/bin/env python3
"""Confronta l'EPUB con l'hash SHA-256 nella busta Hedera HCS pubblica.

Esempio:
  python3 NOTARIZZAZIONI/verifica_epub.py --epub la-matrice-1.1.5.epub --versione 1.1.5 --lingua it --sequenza 17
Nessuna chiave, libreria esterna o account necessario.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen

TOPIC = "0.0.10926025"
MIRROR = "https://mainnet-public.mirrornode.hedera.com"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_record(topic: str, seq: int, endpoint: str, saved: Optional[str]) -> dict:
    if saved:
        return json.loads(Path(saved).read_text(encoding="utf-8"))
    url = endpoint.rstrip("/") + "/api/v1/topics/{}/messages/{}".format(topic, seq)
    with urlopen(Request(url, headers={"User-Agent": "matrice-epub-verifier/1.0"}),
                 timeout=30) as response:
        return json.load(response)


def verify(args) -> None:
    p = Path(args.epub)
    if not p.is_file():
        raise ValueError("EPUB non trovato: {}".format(p))
    response = load_record(args.topic, args.sequenza, args.mirror, args.mirror_json)
    if response.get("topic_id") != args.topic:
        raise ValueError("Topic HCS inatteso")
    if response.get("sequence_number") != args.sequenza:
        raise ValueError("Sequenza HCS inattesa")
    if not response.get("consensus_timestamp"):
        raise ValueError("Timestamp di consenso assente")
    raw = base64.b64decode(response["message"], validate=True)
    busta = json.loads(raw.decode("utf-8"))
    if not isinstance(busta, dict):
        raise ValueError("Busta HCS non JSON object")
    if busta.get("lingua") != args.lingua or busta.get("versione") != args.versione:
        raise ValueError("Lingua o versione non corrispondono")
    expected = busta.get("epub_sha256")
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise ValueError("Campo epub_sha256 mancante o non valido")
    actual = digest_file(p)
    if actual != expected:
        raise ValueError("EPUB diverso da quello attestato: {} != {}".format(actual, expected))
    if args.manifest:
        m = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        matches = [x for x in m.get("outputs", []) if str(x.get("path", "")).lower().endswith(".epub")]
        if len(matches) != 1:
            raise ValueError("Manifesto ambiguo: trovati {} EPUB".format(len(matches)))
        if matches[0].get("sha256") != actual or (matches[0].get("size") is not None and matches[0]["size"] != p.stat().st_size):
            raise ValueError("Impronta o dimensione EPUB differisce dal manifesto")
        canon = json.dumps(m, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(canon).hexdigest() != busta.get("manifest_digest"):
            raise ValueError("Digest del manifesto non corrisponde a Hedera")
    print("VERIFICATO: byte EPUB identici all'attestazione HCS")
    print("Versione: {}, lingua: {}".format(args.versione, args.lingua))
    print("SHA-256: {}".format(actual))
    print("Topic: {}, sequenza: {}".format(args.topic, args.sequenza))
    print("Consenso: {}".format(response["consensus_timestamp"]))
    print("La verifica non dimostra veridicita' del contenuto o disponibilita' futura.")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--epub", required=True, help="EPUB definitivo scaricato")
    p.add_argument("--versione", required=True)
    p.add_argument("--lingua", choices=("it", "en", "es"), required=True)
    p.add_argument("--sequenza", type=int, required=True)
    p.add_argument("--topic", default=TOPIC)
    p.add_argument("--mirror", default=MIRROR)
    p.add_argument("--mirror-json", help="Risposta mirror salvata, verifica offline")
    p.add_argument("--manifest", help="Manifesto release finale, verifica aggiuntiva")
    args = p.parse_args()
    if args.sequenza < 1:
        p.error("sequenza deve essere positiva")
    try:
        verify(args)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("VERIFICA FALLITA: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

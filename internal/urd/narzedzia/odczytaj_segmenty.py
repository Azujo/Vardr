#!/usr/bin/env python3
"""Vardr – niezależny odczyt i sprawdzenie eksportu archiwum NIS2 (Urd).

Wymaga tylko Pythona 3.8+ (biblioteka standardowa), bez Vardra.

  python3 odczytaj_segmenty.py paczka.tar
      sprawdza sumy SHA256SUMS, łańcuch manifestów, segmenty względem
      manifestów, sumę każdej paczki agenta oraz to, że czytelne pliki
      zdarzenia/*.ndjson.gz zawierają dokładnie te same zdarzenia
      (te same identyfikatory i ten sam oryginalny XML) co oryginały.

  python3 odczytaj_segmenty.py paczka.tar --wypisz > zdarzenia.ndjson
      wypisuje zdarzenia odczytane wprost z oryginalnych segmentów
      (agent, czas przyjęcia, paczka, identyfikator, kanał, oryginalny XML).

Format segmentu: nagłówek b"HEIMURD1", potem rekordy: uint32 BE długość
metadanych, metadane JSON, uint32 BE długość treści, treść – paczka agenta
(gzip, JSON: {"events": [{"id", "source", "raw", ...}]}).
"""
import gzip
import hashlib
import io
import json
import struct
import sys
import tarfile

MAGIC = b"HEIMURD1"
MASK = (1 << 64) - 1


def records(data):
    if not data.startswith(MAGIC):
        raise ValueError("brak nagłówka HEIMURD1")
    pos = len(MAGIC)
    while pos < len(data):
        (n,) = struct.unpack(">I", data[pos:pos + 4])
        meta = json.loads(data[pos + 4:pos + 4 + n])
        pos += 4 + n
        (m,) = struct.unpack(">I", data[pos:pos + 4])
        payload = data[pos + 4:pos + 4 + m]
        pos += 4 + m
        if len(payload) != m:
            raise ValueError("ucięty rekord")
        yield meta, payload


class Digest:
    """Skrót zbioru zdarzeń niezależny od kolejności (jak w Vardrze)."""

    def __init__(self):
        self.n, self.a, self.b = 0, 0, 0

    def add(self, batch_sha, event_id, raw):
        s = hashlib.sha256(batch_sha.encode() + b"\0" + event_id.encode() + b"\0" + raw.encode()).digest()
        self.n += 1
        self.a = (self.a + int.from_bytes(s[:8], "big")) & MASK
        self.b = (self.b + int.from_bytes(s[8:16], "big")) & MASK

    def __eq__(self, other):
        return (self.n, self.a, self.b) == (other.n, other.a, other.b)


def sha256_member(tar, member):
    h = hashlib.sha256()
    f = tar.extractfile(member)
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    print_events = "--wypisz" in sys.argv[2:]
    problems = []
    tar = tarfile.open(sys.argv[1])
    members = {m.name: m for m in tar.getmembers() if m.isfile()}

    # 1. Sumy wszystkich plików.
    sums = {}
    for line in tar.extractfile(members["SHA256SUMS"]).read().decode().splitlines():
        digest, name = line.split("  ", 1)
        sums[name] = digest
    for name, member in members.items():
        if name == "SHA256SUMS":
            continue
        if name not in sums:
            problems.append(f"plik {name} spoza SHA256SUMS")
        elif sha256_member(tar, member) != sums[name]:
            problems.append(f"plik {name}: SHA-256 niezgodny z SHA256SUMS")
    for name in sums:
        if name not in members:
            problems.append(f"brak pliku {name}")

    # 2. Łańcuch manifestów (każdy wskazuje SHA-256 poprzedniego).
    info = json.loads(tar.extractfile(members["export.json"]).read())
    expected_segments = {}
    prev = None
    for seq in range(info["chain"]["from_seq"], info["chain"]["to_seq"] + 1):
        raw = tar.extractfile(members[f"chain/{seq:08d}.json"]).read()
        manifest = json.loads(raw)
        if prev is not None and manifest["prev_sha256"] != prev:
            problems.append(f"manifest {seq}: łańcuch przerwany")
        prev = hashlib.sha256(raw).hexdigest()
        if seq in {m["seq"] for m in info["manifests"]}:
            for s in manifest["segments"]:
                expected_segments[s["path"]] = s
    if prev != info["latest_manifest"]["sha256"]:
        problems.append("najnowszy manifest nie zgadza się z kotwicą w export.json")

    # 3. Segmenty: zgodność z manifestem, suma każdej paczki, zdarzenia.
    original = Digest()
    selected = set(info.get("agents") or [])
    out = sys.stdout
    for path, seg in sorted(expected_segments.items()):
        if path not in members:
            problems.append(f"brak segmentu {path}")
            continue
        data = tar.extractfile(members[path]).read()
        if hashlib.sha256(data).hexdigest() != seg["sha256"]:
            problems.append(f"segment {path}: SHA-256 niezgodny z manifestem")
        for meta, payload in records(data):
            batch_sha = hashlib.sha256(payload).hexdigest()
            if batch_sha != meta["sha256"]:
                problems.append(f"segment {path}: paczka {meta.get('batch')} niezgodna ze swoją sumą")
                continue
            try:
                batch = json.loads(gzip.decompress(payload))
            except Exception:  # paczka nieczytelna – w czytelnej części jest wpis z błędem
                continue
            # Eksport ograniczony do wybranych agentów: część czytelna
            # zawiera tylko ich zdarzenia (segmenty są zawsze kompletne).
            if selected and meta["agent"] not in selected:
                continue
            for ev in batch.get("events", []):
                original.add(batch_sha, ev["id"], ev.get("raw", ""))
                if print_events:
                    out.write(json.dumps({"agent": meta["agent"], "received_at": meta["received_at"],
                                          "batch_id": meta.get("batch", ""), "batch_sha256": batch_sha,
                                          "event_id": ev["id"], "channel": ev.get("source", ""),
                                          "xml": ev.get("raw", "")}, ensure_ascii=False) + "\n")
    if print_events:
        return 0

    # 4. Czytelne zdarzenia muszą odpowiadać oryginałom.
    readable = Digest()
    for name in info.get("readable", {}).get("files", []):
        with gzip.open(tar.extractfile(members[name])) as f:
            for line in io.TextIOWrapper(f, encoding="utf-8"):
                r = json.loads(line)
                # Pola vardr.*; eksporty sprzed zmiany nazwy projektu mają heimdall.*.
                p = "vardr." if "vardr.event_id" in r or "vardr.error" in r else "heimdall."
                if r.get(p + "error"):
                    continue
                readable.add(r[p + "batch_sha256"], r[p + "event_id"], r.get("event.original", ""))
    if readable != original:
        problems.append(f"czytelne zdarzenia ({readable.n}) nie odpowiadają oryginałom ({original.n})")

    print(f"eksport {info['export_id']}: {len(expected_segments)} segmentów, {original.n} zdarzeń z oryginałów")
    if selected:
        print("część czytelna tylko z agentów: " + ", ".join(sorted(selected)))
    print(f"kotwica (SHA-256 najnowszego manifestu): {info['latest_manifest']['sha256']}")
    if problems:
        print("NIEZGODNOŚCI:")
        for p in problems:
            print("  -", p)
        return 1
    print("wynik: zgodne – czytelne zdarzenia pochodzą z nienaruszonych oryginałów")
    return 0


if __name__ == "__main__":
    sys.exit(main())

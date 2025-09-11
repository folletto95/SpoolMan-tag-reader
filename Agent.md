# Bambu NFC Reader – Setup Repo

Questo documento contiene tutte le istruzioni e i file necessari per creare la repository **bambu-nfc-reader** su GitHub.  
Il progetto serve a leggere e catalogare le tag NFC delle bobine BambuLab usando un **Raspberry Pi + PN532 USB**.

---

## 1. Creazione repository GitHub
- Nome repo: **bambu-nfc-reader**
- Descrizione: Tool per leggere e catalogare le tag NFC delle bobine BambuLab con Raspberry Pi + PN532.
- Licenza: GPL-3.0
- Inizializzare **senza** README, .gitignore, né licenza (li aggiungiamo noi).

---

## 2. Struttura della repository

bambu-nfc-reader/
├── README.md
├── requirements.txt
├── Agent.md
├── src/
│ ├── reader.py
│ ├── parser.py
│ └── utils.py
└── examples/
└── dump_example.json

---

## 3. Contenuto dei file

### 📄 requirements.txt
```txt
nfcpy==1.0.4
pyserial
```

### 📄 src/reader.py
```python
import nfc
import json
import binascii
from datetime import datetime

OUTPUT_FILE = f"bambu_tag_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def on_connect(tag):
    print(f"[INFO] Tag trovato: {tag}")
    dump_data = {}

    # UID
    dump_data["uid"] = binascii.hexlify(tag.identifier).decode()

    # Prova a leggere tutti i blocchi possibili
    if hasattr(tag, 'dump'):
        blocks = []
        for i, block in enumerate(tag.dump()):
            block_hex = binascii.hexlify(block).decode()
            blocks.append({"index": i, "data": block_hex})
            dump_data["blocks"] = blocks

    # Salva su file JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(dump_data, f, indent=2)

    print(f"[INFO] Dump salvato in {OUTPUT_FILE}")
    return True

def main():
    print("[INFO] Avvio lettore NFC...")
    with nfc.ContactlessFrontend('usb') as clf:
        clf.connect(rdwr={'on-connect': on_connect})

if __name__ == "__main__":
    main()
```

### 📄 src/parser.py
```python
# Parser di base per future estensioni
# Qui potrai aggiungere funzioni che interpretano i dati dei blocchi Bambu

def parse_blocks(blocks):
    parsed = {}
    # TODO: implementare la logica di parsing delle tag Bambu
    parsed["raw_blocks"] = blocks
    return parsed
```

### 📄 src/utils.py
```python
# Utility functions per il progetto

def hex_to_ascii(hex_str):
    try:
        return bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
    except Exception:
        return None
```

### 📄 examples/dump_example.json
```json
{
  "uid": "04a224b3d82180",
  "blocks": [
    {"index": 0, "data": "0411223344556677"},
    {"index": 1, "data": "deadbeefcafebabe"}
  ]
}
```

### 📄 README.md
```markdown
# Bambu NFC Reader

Un tool per **leggere e catalogare le tag NFC delle bobine BambuLab** usando un **Raspberry Pi + PN532 USB**.

## 🚀 Setup

1. Clona la repo:
   ```bash
   git clone https://github.com/<tuo-utente>/bambu-nfc-reader.git
   cd bambu-nfc-reader
   ```

Crea un virtualenv:

python3 -m venv .venv
source .venv/bin/activate

Installa le dipendenze:

pip install -r requirements.txt

Collega il PN532 USB al Raspberry.

## ▶️ Uso

Esegui il lettore:

python src/reader.py

Appoggia una bobina Bambu sul lettore. Verrà generato un file JSON con:

UID della tag

Dump di tutti i blocchi disponibili

## 📂 Output

Esempio bambu_tag_20250910_123456.json:

{
  "uid": "04a224b3d82180",
  "blocks": [
    {"index": 0, "data": "0411223344556677"},
    {"index": 1, "data": "deadbeefcafebabe"}
  ]
}

## 🔮 Roadmap

Parsing automatico dei campi noti (materiale, colore, peso iniziale)

Integrazione diretta con Spoolman

Web UI per consultare il catalogo materiali
```

---

## 4. Comandi Git

```bash
git init
git add .
git commit -m "Initial commit - Bambu NFC Reader base"
git branch -M main
git remote add origin git@github.com:<tuo-utente>/bambu-nfc-reader.git
git push -u origin main
```

## ✅ Risultato atteso

Una repo GitHub funzionante con:

- Script Python per leggere tag NFC Bambu
- Output JSON di esempio
- Documentazione chiara per setup e utilizzo
- Roadmap per futuri sviluppi (parsing, Spoolman, UI)

---

# Bambu NFC Reader

Un tool per **leggere e catalogare le tag NFC delle bobine BambuLab** usando un **Raspberry Pi + PN532 USB**.

## 🚀 Setup

1. Clona la repo:
   ```bash
   git clone https://github.com/<tuo-utente>/bambu-nfc-reader.git
   cd bambu-nfc-reader
   ```

2. Crea un virtualenv:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Installa le dipendenze:
   ```bash
   pip install -r requirements.txt
   ```

4. Collega il PN532 USB al Raspberry.

## ▶️ Uso

Esegui il lettore:
```bash
python src/reader.py
```

Appoggia una bobina Bambu sul lettore. Verrà generato un file JSON con:

- UID della tag
- Dump di tutti i blocchi disponibili
- Decodifica dei campi noti (spool_id, materiale, colore, peso)

## 📂 Output

Esempio `bambu_tag_20250910_123456.json`:
```json
{
  "uid": "04a224b3d82180",
  "blocks": [
    {"index": 0, "data": "0411223344556677"},
    {"index": 1, "data": "deadbeefcafebabe"}
  ],
  "parsed": {
    "spool_id": "unknown",
    "material": null,
    "color": null,
    "weight_grams": null,
    "raw_hex": "0411223344556677deadbeefcafebabe"
  }
}
```

## 🔮 Roadmap

- Espandere il parsing dei campi Bambu (materiale, colore, peso iniziale)
- Integrazione diretta con Spoolman
- Web UI per consultare il catalogo materiali

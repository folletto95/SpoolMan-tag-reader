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

4. Collega il PN532 al Raspberry (via USB o adattatore seriale).

## ▶️ Uso

Esegui il lettore (rilevamento automatico):
```bash
python src/reader.py
```
Il programma proverà a individuare un lettore NFC collegato via USB o
seriale (`/dev/ttyUSB*` o `/dev/ttyACM*`).


Per specificare manualmente il dispositivo:
```bash
python src/reader.py --device 'tty:USB0:pn532'
```

In alternativa puoi impostare la variabile d'ambiente `NFC_DEVICE`:
```bash
export NFC_DEVICE='tty:USB0:pn532'
python src/reader.py

```

Appoggia una bobina Bambu sul lettore. Verrà generato un file JSON con:

- UID della tag
- Dump di tutti i blocchi disponibili
- Decodifica dei campi noti (spool_id, materiale, colore, peso)

## 📂 Output

Oltre al file JSON vengono generati:

- `bambu_tag_YYYYMMDD_HHMMSS.bin` con i dati grezzi concatenati della tag
- `bambu_tag_YYYYMMDD_HHMMSS.dump.txt` con l'output testuale di `dump()` del
  lettore NFC

Questi file aiutano a verificare eventuali problemi di lettura o decodifica.


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

## Licenza

Distribuito sotto licenza GPL-3.0. Vedi [LICENSE](LICENSE) per i dettagli.

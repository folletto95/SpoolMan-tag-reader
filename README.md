# Bambu NFC Reader

Tool per **leggere e catalogare le tag NFC delle bobine BambuLab** usando le
utility di **libnfc** (`nfc-list`, `nfc-mfclassic`).

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

3. Installa le dipendenze Python:
   ```bash
   pip install -r requirements.txt
   ```

4. Assicurati che nel sistema siano presenti gli strumenti di `libnfc`
   (`nfc-list`, `nfc-mfclassic`).

5. Collega il lettore NFC (es. PN532 USB) al dispositivo.

## ▶️ Uso

Esegui il lettore (scarica automaticamente la guida se manca):
```bash
python src/reader.py
```
Il programma esegue `nfc-list` per rilevare il tag, calcola le chiavi con
`deriveKeys.py` e crea un dump con `nfc-mfclassic`; infine lo interpreta con
`parse.py` producendo un file JSON.

Opzioni utili:

* `--guide DIR`  – percorso della cartella `RFID-Tag-Guide` (default:
  `./RFID-Tag-Guide`). Se non esiste viene scaricata automaticamente.
* `--no-auto-fetch` – non scaricare la guida automaticamente.
* `--no-parse` – genera solo il dump `.mfd` senza eseguire `parse.py`.
* `--only-parse FILE.mfd` – salta la lettura e interpreta un dump esistente.
* `--master-key HEX` – usa una master key alternativa (32 caratteri esadecimali) per
  testare chiavi diverse.
* `--show-keys` – stampa a video le chiavi derivate (solo debug).

Appoggia una bobina Bambu sul lettore. Verranno generati:

- `bambu_tag_<timestamp>.mfd` con i dati grezzi della tag
- `bambu_tag_<timestamp>.json` con la decodifica dei campi noti (spool_id,
  materiale, colore, peso)

### Dump con Proxmark3

Per usare un Proxmark3 al posto del lettore PN532:

```bash
python src/tag_dump_pm3.py -o dumps/
```

Il comando deriva automaticamente le chiavi della tag e salva i file `.bin` e
`.json` nella cartella indicata. Aggiungi `--backdoor` se vuoi usare la chiave
di backdoor senza libreria crittografica.


## 📂 Output

Il lettore produce:

- `bambu_tag_YYYYMMDD_HHMMSS.mfd` con il dump completo della tag
- `bambu_tag_YYYYMMDD_HHMMSS.json` con l'interpretazione dei campi principali

I file possono essere usati per analisi successive o per importare i dati in
altre applicazioni.


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

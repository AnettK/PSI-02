**Zadání**

Zadáním druhé semestrální práce na předmět KIV/PSI bylo implementovat aplikace v jazyce Python, která pomocí knihoven **Scapy** a **PySNMP** zjistí topologii sítě.

**Implementace:**

Aplikace byla implementována v jazyce Python s využitím zmiňovaných knihoven Scapy a PySNMP.

Nejdříve si získá z DHCPOffer zprávy adresu výchozí brány a poté pomocí SNMP dotazů získá tzv. "Next hop", tedy další směrovač v síti. Jeho IP adresu si přidá do množiny. Toto dotazování se rekurzivně opakuje až do doby, kdy se ze SNMP dotazu vrátí stejná IP adresa, která je již obsažena v množině.

**Spuštění**

Pro správné fungování se musí nejprve příkazem  `pip install -r requirements.txt` nainstalovat potřebné knihovny.

Aplikace se poté spouští příkazem:

`python3 main.py`

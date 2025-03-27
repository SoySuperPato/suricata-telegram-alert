import os
import json
import time
import datetime
import requests
import pytz  # Para zona horaria UTC

# Configuración de Telegram
TELEGRAM_TOKEN = "TU_TOKEN_DE_BOT"
TELEGRAM_CHAT_ID = "TU_CHAT_ID_O_GRUPO"

# Ruta al archivo de logs de Suricata
EVE_JSON_PATH = "/var/log/suricata/eve.json"

def enviar_alerta_telegram(ip, fecha):
    mensaje = f"🚨 Alerta Suricata\n\nIP: {ip}\nFecha: {fecha}"
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": mensaje}
    requests.post(url, json=data)

def procesar_eventos():
    print("[*] Iniciando monitoreo de alertas Suricata...")
    with open(EVE_JSON_PATH, "r") as archivo:
        archivo.seek(0, os.SEEK_END)  # Ir al final del archivo
        while True:
            linea = archivo.readline()
            if not linea:
                time.sleep(1)
                continue
            try:
                evento = json.loads(linea)
                if evento.get("event_type") == "alert":
                    ip = evento.get("src_ip")
                    fecha = datetime.datetime.now(pytz.utc).isoformat()
                    print(f"[+] Alerta detectada: {ip} @ {fecha}")
                    enviar_alerta_telegram(ip, fecha)
            except Exception as e:
                print(f"[!] Error al procesar línea: {e}")

if __name__ == "__main__":
    procesar_eventos()

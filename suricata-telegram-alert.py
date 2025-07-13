import os
import json
import time
import datetime
import requests
import pytz  # Para zona horaria UTC


# -------------------------------
# CONFIGURACIÓN
# -------------------------------

TELEGRAM_TOKEN = "TU_TOKEN_DE_BOT"
TELEGRAM_CHAT_ID = "TU_CHAT_ID_O_GRUPO"
VT_API_KEY = "TU_TOKEN_DE_VIRUS_TOTAL"
EVE_JSON_PATH = "/var/log/suricata/eve.json"

# -------------------------------
# CONTROL DE FRECUENCIA DE ALERTAS
# -------------------------------

# Diccionario para controlar última alerta enviada: { clave_evento: timestamp }
ultimas_alertas = {}

# Tiempo en segundos para bloqueo (15 minutos)
TIEMPO_BLOQUEO = 15 * 60

def puede_enviar_alerta(clave):
    ahora = time.time()
    ultima = ultimas_alertas.get(clave, 0)

    if ahora - ultima > TIEMPO_BLOQUEO:
        ultimas_alertas[clave] = ahora
        return True
    else:
        return False

# -------------------------------
# FUNCIÓN: Consultar VirusTotal
# -------------------------------
def verificar_virustotal(ip):
    if not ip:
        return "⚠️ IP inválida"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats.get("malicious", 0)
            sospechosos = stats.get("suspicious", 0)
            total = sum(stats.values())

            enlace_vt = f"https://www.virustotal.com/gui/ip-address/{ip}"

            info = (
                f"🧪 *VirusTotal Scan para {ip}:*\n"
                f"{'✅' if maliciosos == 0 else '❌'} Maliciosos: *{maliciosos}*\n"
                f"⚠️ Sospechosos: *{sospechosos}*\n"
                f"🔍 Motores Analizados: *{total}*\n"
                f"🔗 [Ver análisis en VirusTotal]({enlace_vt})"
            )
            return info
        else:
            return f"⚠️ VirusTotal no disponible para {ip} (código {response.status_code})"
    except Exception as e:
        return f"⚠️ VirusTotal Error para {ip}: {e}"

# -------------------------------
# FUNCIÓN: Enviar alerta a Telegram
# -------------------------------
def enviar_alerta_telegram(ip_origen, ip_destino, fecha, signature, info_vt_origen, info_vt_destino):
    mensaje = (
        f"🚨 *Alerta Suricata Detectada*\n\n"
        f"🕒 *Fecha:* {fecha}\n"
        f"🌐 *IP Origen:* `{ip_origen}`\n"
        f"{info_vt_origen}\n\n"
        f"🌐 *IP Destino:* `{ip_destino}`\n"
        f"{info_vt_destino}\n\n"
        f"🛡️ *Regla:* _{signature}_"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensaje,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=data)
        if response.status_code != 200:
            print(f"[!] Error al enviar mensaje a Telegram: {response.text}")
    except Exception as e:
        print(f"[!] Excepción al enviar mensaje a Telegram: {e}")

# -------------------------------
# FUNCIÓN PRINCIPAL: Monitorear Suricata
# -------------------------------
def procesar_eventos():
    print("[*] Iniciando monitoreo de alertas Suricata...")

    tz_santiago = pytz.timezone("America/Santiago")

    with open(EVE_JSON_PATH, "r") as archivo:
        archivo.seek(0, os.SEEK_END)

        while True:
            linea = archivo.readline()

            if not linea:
                time.sleep(1)
                continue

            try:
                evento = json.loads(linea)

                if evento.get("event_type") == "alert":
                    ip_origen = evento.get("src_ip")
                    ip_destino = evento.get("dest_ip")
                    signature = evento.get("alert", {}).get("signature", "Desconocida")

                    fecha = datetime.datetime.now(tz_santiago).isoformat()

                    clave_evento = f"{ip_origen}_{ip_destino}_{signature}"

                    if puede_enviar_alerta(clave_evento):
                        print(f"[+] Alerta detectada: {ip_origen} -> {ip_destino} @ {fecha} - {signature}")
                        info_vt_origen = verificar_virustotal(ip_origen)
                        info_vt_destino = verificar_virustotal(ip_destino)
                        enviar_alerta_telegram(ip_origen, ip_destino, fecha, signature, info_vt_origen, info_vt_destino)
                    else:
                        print(f"[!] Alerta {clave_evento} ignorada para evitar spam.")

            except Exception as e:
                print(f"[!] Error al procesar línea: {e}")

# -------------------------------
# EJECUCIÓN PRINCIPAL
# -------------------------------
if __name__ == "__main__":
    procesar_eventos()

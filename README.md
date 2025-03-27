# 🚨 Suricata Telegram Alert

Este script en Python permite enviar alertas generadas por **Suricata IDS** directamente a un grupo de **Telegram** en tiempo real.

## 📌 Descripción

Monitorea el archivo `eve.json` generado por Suricata y, al detectar eventos de tipo `alert`, extrae la IP de origen y envía automáticamente un mensaje de notificación a un grupo o canal de Telegram.

> ✅ Ideal para entornos de pruebas, SOC o CSIRT que necesiten una alerta rápida y liviana sin infraestructura adicional.

## 🔧 Requisitos

- Suricata configurado para generar `eve.json`
- Python 3.x
- Paquetes:
  - `requests`
  - `pytz`

Puedes instalarlos con:

```bash
pip install requests pytz

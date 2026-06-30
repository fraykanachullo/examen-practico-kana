#!/usr/bin/env python3
"""
Laboratorio 1 - Tarea 1.2: Analizador Forense de Tráfico Web (access.log)
Autor: Fray Kana Chullo (IX Ciclo - Ingeniería de Sistemas)
"""

import os
import re
import json
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), 'access.log')
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), 'reporte_web.json')

# Regex estructurada para el Combined Log Format
LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+\[(?P<timestamp>.*?)\]\s+"(?P<metodo>\w+)\s+(?P<path>.*?)\s+HTTP/.*?"\s+(?P<status>\d{3})'
)

SQLI_PATTERNS = [
    re.compile(r'UNION', re.IGNORECASE),
    re.compile(r'SELECT', re.IGNORECASE),
    re.compile(r'OR\s+\d+=\d+', re.IGNORECASE),
    re.compile(r'--'),
    re.compile(r"'")
]

def parse_timestamp(ts_str):
    ts_clean = ts_str.split()[0]
    return datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")

def analizar_logs_web():
    if not os.path.exists(LOG_PATH):
        raise FileNotFoundError(f"[-] No se encontró {LOG_PATH}")

    historial_peticiones = {}
    agrupacion_errores = {}
    detecciones_sqli = []
    ips_escaneo_detectado = set()

    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        for linea in f:
            match = LOG_REGEX.search(linea)
            if not match:
                continue
                
            ip = match.group('ip')
            ts_raw = match.group('timestamp')
            path = match.group('path')
            status = match.group('status')
            
            try:
                dt_evento = parse_timestamp(ts_raw)
            except ValueError:
                continue

            # Agrupación de respuestas 4xx y 5xx por IP
            if status.startswith('4') or status.startswith('5'):
                if ip not in agrupacion_errores:
                    agrupacion_errores[ip] = {"4xx": 0, "5xx": 0}
                if status.startswith('4'):
                    agrupacion_errores[ip]["4xx"] += 1
                else:
                    agrupacion_errores[ip]["5xx"] += 1

            # Detección de escaneo de directorios (20 peticiones a rutas distintas en < 60s)
            if ip not in historial_peticiones:
                historial_peticiones[ip] = []
            historial_peticiones[ip].append((dt_evento, path))
            
            ventana = [p for p in historial_peticiones[ip] if (dt_evento - p[0]).total_seconds() <= 60]
            historial_peticiones[ip] = ventana
            paths_unicos = set(p[1] for p in ventana)
            if len(paths_unicos) > 20:
                ips_escaneo_detectado.add(ip)

            # Detección de patrones SQL Injection
            for pattern in SQLI_PATTERNS:
                if pattern.search(path):
                    detecciones_sqli.append({
                        "fecha_hora": dt_evento.strftime("%Y-%m-%d %H:%M:%S"),
                        "ip_origen": ip,
                        "uri_solicitada": path,
                        "codigo_respuesta": int(status),
                        "patron_detectado": pattern.pattern
                    })
                    break

    # Imprimir detecciones críticas en consola
    print("\n" + "="*80)
    print(" DETECCIONES DE ESCANEO DE DIRECTORIOS Y SQL INJECTION ")
    print("="*80)
    for ip in ips_escaneo_detectado:
        print(f"[ALERTA WEB] Escaneo de directorios detectado desde la IP: {ip}")
    for sqli in detecciones_sqli[:10]: # Mostrar los 10 primeros en consola
        print(f"[ALERTA SQLi] IP: {sqli['ip_origen']} intentó SQLi en: {sqli['uri_solicitada'][:50]}")

    # Guardar en reporte_web.json
    reporte_final = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ips_con_escaneo_directorios": list(ips_escaneo_detectado),
        "errores_http_por_ip": agrupacion_errores,
        "intentos_sql_injection": detecciones_sqli
    }

    with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
        json.dump(reporte_final, jf, indent=4, ensure_ascii=False)
        
    print(f"\n[+] Reporte Web exportado correctamente a: {OUTPUT_JSON}")

if __name__ == "__main__":
    analizar_logs_web()
#!/usr/bin/env python3
"""
Laboratorio 1 - Tarea 1.1: Analizador Forense de Logs SSH (auth.log)
Autor: Fray Kana Chullo (IX Ciclo - Ingeniería de Sistemas)
"""

import os
import re
import json
from collections import Counter
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(__file__), 'auth.log')
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), 'reporte_ssh.json')
UMBRAL_ALERTA = 50

# Expresión regular para capturar la IP de intentos fallidos
SSH_FAILED_REGEX = re.compile(r'Failed password for .* from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

def analizar_logs_ssh():
    if not os.path.exists(LOG_PATH):
        raise FileNotFoundError(f"[-] No se encontró {LOG_PATH}")

    intentos_fallidos_por_ip = Counter()

    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        for linea in f:
            match = SSH_FAILED_REGEX.search(linea)
            if match:
                ip = match.group('ip')
                intentos_fallidos_por_ip[ip] += 1

    top_10_atacantes = intentos_fallidos_por_ip.most_common(10)
    
    # Imprimir Ranking ordenado en consola
    print("\nRANKING TOP 10 IPS CON MÁS INTENTOS FALLIDOS:")
    for idx, (ip, conteo) in enumerate(top_10_atacantes):
        print(f"{idx+1}. IP: {ip} - Intentos: {conteo}")

    print("\n" + "="*80)
    print(" ALERTAS DE SEGURIDAD DISPARADAS ")
    print("="*80)
    
    ips_sospechosas_list = []
    total_global_fallidos = sum(intentos_fallidos_por_ip.values())

    for ip, conteo in intentos_fallidos_por_ip.items():
        es_alerta = conteo > UMBRAL_ALERTA
        if es_alerta:
            # Formato de mensaje estricto de la guía del examen
            print(f"[ALERTA] IP: {ip} {conteo} intentos fallidos Posible ataque de fuerza bruta")
            
        ips_sospechosas_list.append({
            "ip": ip,
            "intentos": conteo,
            "alerta": es_alerta
        })

    # Estructura JSON exacta de la guía del examen
    reporte_final = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_global_fallidos,
        "ips_sospechosas": sorted(ips_sospechosas_list, key=lambda x: x['intentos'], reverse=True)
    }

    with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
        json.dump(reporte_final, jf, indent=4, ensure_ascii=False)
        
    print("\n" + "="*80)
    print(f"[+] Reporte estructurado exportado a: {OUTPUT_JSON}")
    print("="*80)

if __name__ == "__main__":
    analizar_logs_ssh()
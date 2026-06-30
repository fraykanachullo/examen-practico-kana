#!/usr/bin/env python3
"""
Script de Predicción - Detección de Anomalías
Autor: Fray Kana Chullo (IX Ciclo - Ingeniería de Sistemas)
Fecha: 2026-06-30
Uso: python predecir.py <archivo.csv>
"""

import pandas as pd
import numpy as np
import joblib
import sys
import os
from datetime import datetime

def load_model():
    """Carga el modelo y el scaler guardados"""
    try:
        model = joblib.load('modelo_anomalias.pkl')
        scaler = joblib.load('scaler.pkl')
        with open('features.txt', 'r') as f:
            features = [line.strip() for line in f.readlines()]
        return model, scaler, features
    except FileNotFoundError as e:
        print(f"❌ Error: No se encontró el archivo requerido: {e.filename}")
        sys.exit(1)

def predict_anomalies(filepath):
    """Predice anomalías en el archivo CSV"""
    print("=" * 60)
    print("DETECCIÓN DE ANOMALÍAS EN TRÁFICO DE RED")
    print("=" * 60)
    print(f"Autor: Fray Kana Chullo")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    if not os.path.exists(filepath):
        print(f"❌ Error: El archivo '{filepath}' no existe.")
        return
    
    df = pd.read_csv(filepath)
    print(f"📂 Total de registros: {len(df)}")
    
    model, scaler, features = load_model()
    print("✅ Modelo cargado exitosamente")
    
    # Feature engineering
    df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
    df['bytes_per_sec'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 0.1)
    
    X = df[features]
    X_scaled = scaler.transform(X)
    
    predictions = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    
    results = df.copy()
    results['prediction'] = ['anomaly' if p == -1 else 'normal' for p in predictions]
    results['anomaly_score'] = scores
    
    anomalies = results[results['prediction'] == 'anomaly']
    
    print("-" * 60)
    print(f"📊 RESULTADOS:")
    print(f"   Total: {len(results)}")
    print(f"   🔴 Anomalías: {len(anomalies)} ({len(anomalies)/len(results)*100:.2f}%)")
    print(f"   🟢 Normales: {len(results) - len(anomalies)}")
    print("-" * 60)
    
    if len(anomalies) > 0:
        print("\n🔴 TOP 5 ANOMALÍAS:")
        for idx, row in anomalies.head(5).iterrows():
            print(f"\n  📌 {row.get('src_ip', 'N/A')} -> {row.get('dst_ip', 'N/A')}")
            print(f"     Bytes: {row.get('bytes_sent', 0):.0f} sent / {row.get('bytes_recv', 0):.0f} recv")
            print(f"     Duración: {row.get('duration_sec', 0):.2f}s")
            print(f"     Score: {row['anomaly_score']:.4f}")
    
    output_file = f"resultados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    results.to_csv(output_file, index=False)
    print(f"\n💾 Resultados guardados en: {output_file}")
    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python predecir.py <archivo.csv>")
        sys.exit(1)
    predict_anomalies(sys.argv[1])

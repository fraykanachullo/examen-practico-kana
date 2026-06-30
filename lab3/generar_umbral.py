#!/usr/bin/env python3
"""
Generación de SCR-3.3: Curva Umbral vs F1 y Top 10 Anomalías
Autor: Fray Kana Chullo
Fecha: 2026-06-30
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
import joblib
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("Generando SCR-3.3: Curva Umbral vs F1 y Top 10 Anomalías")
print("="*60)

# 1. Cargar datos
df = pd.read_csv('network_traffic.csv')
print(f"✅ Dataset cargado: {df.shape}")

# 2. Feature Engineering
df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_per_sec'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 0.1)

# 3. Preparar datos
feature_cols = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets', 'bytes_ratio', 'bytes_per_sec']
X = df[feature_cols].copy()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 4. Entrenar modelo
model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
model.fit(X_scaled)

# 5. Obtener scores
scores = model.decision_function(X_scaled)
y_true = df['label'].values

# 6. Calcular curva Umbral vs F1
print("\n📊 Calculando curva Umbral vs F1...")
thresholds = np.linspace(-0.5, 0.5, 50)
f1_scores = []
precisions = []
recalls = []

for thresh in thresholds:
    y_pred = ['anomaly' if score < thresh else 'normal' for score in scores]
    f1_scores.append(f1_score(y_true, y_pred, pos_label='anomaly'))
    precisions.append(precision_score(y_true, y_pred, pos_label='anomaly', zero_division=0))
    recalls.append(recall_score(y_true, y_pred, pos_label='anomaly'))

# Encontrar umbral óptimo
best_idx = np.argmax(f1_scores)
best_threshold = thresholds[best_idx]
best_f1 = f1_scores[best_idx]

print(f"✅ Umbral óptimo: {best_threshold:.3f}")
print(f"✅ Mejor F1-Score: {best_f1:.3f}")

# 7. Graficar curva Umbral vs F1
fig, ax = plt.subplots(figsize=(10, 6))
ax.plot(thresholds, f1_scores, 'b-', label='F1-Score', linewidth=2)
ax.plot(thresholds, precisions, 'g--', label='Precisión', linewidth=2)
ax.plot(thresholds, recalls, 'r--', label='Recall', linewidth=2)
ax.axvline(best_threshold, color='black', linestyle=':', label=f'Umbral óptimo ({best_threshold:.3f})')
ax.set_xlabel('Umbral de Anomalía')
ax.set_ylabel('Score')
ax.set_title('Curva Umbral vs F1-Score, Precisión y Recall')
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('evidencias/SCR-3.3_umbral_f1.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ SCR-3.3_umbral_f1.png guardado")

# 8. Top 10 Anomalías
print("\n📊 Top 10 Anomalías...")
anomaly_indices = np.argsort(scores)[:10]
top_anomalies = df.iloc[anomaly_indices][['timestamp', 'src_ip', 'dst_ip', 'bytes_sent', 'bytes_recv', 'duration_sec', 'label']].copy()
top_anomalies['score'] = scores[anomaly_indices]
print(top_anomalies)

# 9. Explicación de anomalías
print("\n📝 EXPLICACIÓN DE ANOMALÍAS:")
for idx, row in top_anomalies.iterrows():
    print(f"\n  🔴 {row['src_ip']} -> {row['dst_ip']}")
    print(f"     Bytes: {row['bytes_sent']/1e6:.2f} MB enviados / {row['bytes_recv']/1e6:.2f} MB recibidos")
    print(f"     Duración: {row['duration_sec']:.2f} segundos")
    print(f"     Score: {row['score']:.4f}")
    print(f"     Etiqueta real: {row['label']}")
    if row['bytes_sent'] > 500000000:
        print("     ⚠️ POSIBLE EXFILTRACIÓN: Tráfico saliente masivo")
    if row['duration_sec'] > 1000:
        print("     ⚠️ CONEXIÓN PROLONGADA: Duración anormalmente larga")

print("\n" + "="*60)
print("✅ SCR-3.3 GENERADO EXITOSAMENTE")
print("="*60)

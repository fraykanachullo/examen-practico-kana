#!/usr/bin/env python3
"""
LAB 3: Detección de Anomalías con Isolation Forest
Ejecución directa desde terminal
Autor: Fray Kana Chullo
Fecha: 2026-06-30
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
import joblib
import warnings
warnings.filterwarnings('ignore')

print("="*60)
print("LAB 3: Detección de Anomalías con Isolation Forest")
print("Autor: Fray Kana Chullo (IX Ciclo - Ingeniería de Sistemas)")
print("="*60)

# 1. Cargar dataset
print("\n1. CARGANDO DATASET...")
df = pd.read_csv('network_traffic.csv')
print(f"Dimensiones: {df.shape}")
print(f"Columnas: {df.columns.tolist()}")

# 2. Estadísticas
print("\n2. ESTADÍSTICAS DESCRIPTIVAS...")
print(df.describe())
print(f"\nValores nulos: {df.isnull().sum().sum()}")
print(f"Distribución de etiquetas:\n{df['label'].value_counts()}")

# 3. Feature Engineering
print("\n3. FEATURE ENGINEERING...")
df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_per_sec'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 0.1)
print("✅ Nuevas features creadas: bytes_ratio, bytes_per_sec")

# 4. Preparar datos
print("\n4. PREPARANDO DATOS...")
feature_cols = ['bytes_sent', 'bytes_recv', 'duration_sec', 'packets', 'bytes_ratio', 'bytes_per_sec']
X = df[feature_cols].copy()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print(f"✅ Datos normalizados - Shape: {X_scaled.shape}")

# 5. Entrenar modelo
print("\n5. ENTRENANDO ISOLATION FOREST...")
model = IsolationForest(contamination=0.05, n_estimators=100, random_state=42)
model.fit(X_scaled)

y_pred = model.predict(X_scaled)
y_pred_labels = ['anomaly' if p == -1 else 'normal' for p in y_pred]
print("✅ Modelo entrenado")

# 6. Evaluación
print("\n6. EVALUACIÓN...")
y_true = df['label'].values

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(y_true, y_pred_labels))

precision = precision_score(y_true, y_pred_labels, pos_label='anomaly')
recall = recall_score(y_true, y_pred_labels, pos_label='anomaly')
f1 = f1_score(y_true, y_pred_labels, pos_label='anomaly')

print(f"\nPrecisión: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-Score: {f1:.4f}")

# 7. Matriz de Confusión
print("\n7. MATRIZ DE CONFUSIÓN...")
cm = confusion_matrix(y_true, y_pred_labels, labels=['normal', 'anomaly'])
print(cm)

plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['normal', 'anomaly'], 
            yticklabels=['normal', 'anomaly'])
plt.title('Matriz de Confusión - Isolation Forest')
plt.xlabel('Predicción')
plt.ylabel('Real')
plt.tight_layout()
plt.savefig('evidencias/SCR-3.2_metricas.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Matriz de confusión guardada en evidencias/SCR-3.2_metricas.png")

# 8. EDA - Histogramas (SCR-3.1)
print("\n8. GENERANDO GRÁFICAS EDA...")
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
df['bytes_sent'].hist(bins=50, ax=axes[0], edgecolor='black')
axes[0].set_title('Distribución de Bytes Enviados')
axes[0].set_xlabel('Bytes Enviados')
axes[0].set_ylabel('Frecuencia')

df['duration_sec'].hist(bins=50, ax=axes[1], edgecolor='black')
axes[1].set_title('Distribución de Duración (segundos)')
axes[1].set_xlabel('Duración (segundos)')
axes[1].set_ylabel('Frecuencia')

plt.tight_layout()
plt.savefig('evidencias/SCR-3.1_eda.png', dpi=300, bbox_inches='tight')
plt.close()
print("✅ Gráficas EDA guardadas en evidencias/SCR-3.1_eda.png")

# 9. Top 10 Anomalías (SCR-3.3)
print("\n9. TOP 10 ANOMALÍAS...")
scores = model.decision_function(X_scaled)
anomaly_indices = np.argsort(scores)[:10]
top_anomalies = df.iloc[anomaly_indices][['timestamp', 'src_ip', 'dst_ip', 'bytes_sent', 'bytes_recv', 'duration_sec', 'label']].copy()
top_anomalies['score'] = scores[anomaly_indices]
print(top_anomalies)

# 10. Guardar modelo
print("\n10. EXPORTANDO MODELO...")
joblib.dump(model, 'modelo_anomalias.pkl')
joblib.dump(scaler, 'scaler.pkl')
with open('features.txt', 'w') as f:
    for feat in feature_cols:
        f.write(f"{feat}\n")
print("✅ Modelo exportado: modelo_anomalias.pkl, scaler.pkl, features.txt")

print("\n" + "="*60)
print("✅ LAB 3 COMPLETADO EXITOSAMENTE")
print("="*60)

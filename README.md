# Examen Práctico Final de Seguridad Informática - IX Ciclo

## Autor: Fray Kana Chullo

---

## 📋 Información General

| Campo | Valor |
|-------|-------|
| **Curso** | Seguridad Informática |
| **Ciclo** | IX Ciclo - Ingeniería de Sistemas |
| **Fecha** | 2026-06-30 |
| **Competencia** | Diseño e implementación de sistemas de monitoreo de seguridad utilizando herramientas SIEM y técnicas de análisis de eventos en tiempo real, integrando inteligencia artificial para la detección de anomalías y respondiendo proactivamente a incidentes en entornos empresariales. |
| **Repositorio** | [examen-practico-kana](https://github.com/fraykanachullo/examen-practico-kana) |

---

## 🖥️ Infraestructura y Entorno de Trabajo

### Máquina Física
- **OS:** Windows 10
- **Virtualización:** VirtualBox 7.0
- **Herramientas:** VS Code, Git CLI, PowerShell

### Máquinas Virtuales

| Nombre | IP | OS | Propósito |
|--------|----|----|-----------|
| **Ubuntu Endpoint** | 192.168.56.20 | Ubuntu 22.04 LTS | Ejecución de scripts de análisis y ML |
| **Wazuh SIEM Server** | 192.168.56.10 | Ubuntu 22.04 LTS | Servidor central de monitoreo SIEM |
| **Kali Linux** | 192.168.56.30 | Kali 2024.1 | Simulación de ataques y auditorías |

### Red Interna
- **Tipo:** Host-Only / Red Interna
- **Subred:** 192.168.56.0/24

---

## 🛠️ Versiones de Herramientas

| Herramienta | Versión | Propósito |
|-------------|---------|-----------|
| **Python** | 3.12.3 | Scripts de análisis forense y ML |
| **matplotlib** | 3.8.4 | Generación de gráficas de análisis |
| **pandas** | 2.2.2 | Manipulación y análisis de datos |
| **numpy** | 1.26.4 | Operaciones numéricas |
| **scikit-learn** | 1.4.2 | Modelo ML (Isolation Forest) |
| **seaborn** | 0.13.2 | Visualización avanzada de datos |
| **joblib** | 1.4.2 | Serialización de modelos ML |
| **Wazuh** | 4.8.0 | SIEM y monitoreo de seguridad |
| **Elastic Stack** | 8.13.0 | Búsqueda y visualización de datos |
| **Wazuh Dashboard** | 4.8.0 | Dashboard de monitoreo SOC |
| **Jupyter Notebook** | 7.1.2 | Desarrollo interactivo de ML |

---

## 📁 Estructura del Proyecto
examen-practico-kana/
├── README.md # Documentacion principal
├── lab1/ # Analisis Forense de Logs (5 pts)
│ ├── analizar_ssh.py # Analisis de logs SSH
│ ├── analizar_web.py # Analisis de logs Web
│ ├── visualizar.py # Generacion de graficas
│ ├── reporte_ssh.json # Reporte SSH generado
│ ├── reporte_web.json # Reporte Web generado
│ ├── graficas/ # Imagenes generadas
│ │ ├── top10_ssh.png
│ │ ├── timeline_http.png
│ │ └── heatmap_http.png
│ └── evidencias/ # Screenshots requeridos
│ ├── SCR-1.1a_ssh_ejecucion.png
│ ├── SCR-1.1b_ssh_json.png
│ ├── SCR-1.2a_web_ejecucion.png
│ └── SCR-1.2b_web_json.png
├── lab2/ # Reglas de Correlacion Wazuh (4 pts)
│ ├── local_rules.xml # Reglas personalizadas fusionadas
│ ├── local_rules_ssh.xml # Reglas de fuerza bruta SSH
│ ├── local_rules_exfil.xml # Reglas de exfiltracion
│ ├── simular_bruteforce.sh # Simulacion de ataque
│ └── evidencias/ # Screenshots requeridos
│ ├── Wazu activo(scr2.1).png
│ ├── reglas validadas (SCR-2.2).png
│ ├── alertas generadas (SCR-2.3).png
│ └── alerts_sample.log
├── lab3/ # ML - Deteccion de Anomalias (6 pts)
│ ├── network_traffic.csv # Dataset (10,000 registros)
│ ├── deteccion_anomalias.ipynb # Notebook principal
│ ├── predecir.py # Script de produccion
│ ├── ejecutar_lab3.py # Script de entrenamiento
│ ├── generar_umbral.py # Script de umbral F1
│ ├── modelo_anomalias.pkl # Modelo entrenado
│ ├── scaler.pkl # Scaler guardado
│ ├── features.txt # Lista de features
│ ├── nuevo_trafico.csv # Datos de prueba
│ └── evidencias/ # Screenshots requeridos
│ ├── SCR-3.1_eda.png
│ ├── SCR-3.2_metricas.png
│ ├── SCR-3.3_umbral_f1.png
│ └── SCR-3.4_predecir_real.txt
└── lab4/ # Dashboard SOC (5 pts)
├── dashboard_soc.json # Export del dashboard
├── datasource_config.json # Configuracion de fuente
└── evidencias/ # Screenshots requeridos
├── herramienta_usada.txt
├── SCR-4.1_fuente_datos.txt
├── SCR-4.2_visualizaciones.txt
├── SCR-4.3_dashboard.txt
└── SCR-4.4_alerta.txt

text

---

## 🚀 Guia de Instalacion y Configuracion

### 1. Configuracion de Python (Ubuntu Endpoint)

```bash
# Instalar Python 3.12+
sudo apt update
sudo apt install python3.12 python3-pip -y

# Instalar dependencias
pip3 install --break-system-packages matplotlib pandas numpy seaborn scikit-learn joblib
2. Configuracion de Wazuh (Servidor SIEM)
bash
# Instalacion All-in-One
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo apt-get install wazuh-manager -y

# Instalar Elastic Stack
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update
sudo apt-get install elasticsearch kibana logstash -y

# Verificar servicios
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
3. Configuracion de Wazuh Dashboard
bash
# Editar configuracion
sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml

# Configuracion correcta
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: ["https://localhost:9200"]
opensearch.ssl.verificationMode: none
opensearch.username: admin
opensearch.password: admin
server.ssl.enabled: false
uiSettings.overrides.defaultRoute: /app/wazuh

# Reiniciar
sudo systemctl restart wazuh-dashboard
🔄 Ejecucion de Laboratorios
Laboratorio 1: Analisis Forense de Logs
bash
cd ~/examen-practico-kana/lab1

# Dar permisos de ejecucion
chmod +x *.py

# Ejecutar scripts
python3 analizar_ssh.py
python3 analizar_web.py
python3 visualizar.py

# Verificar archivos generados
ls -la *.json
ls -la graficas/
Resultados obtenidos:

Total intentos fallidos SSH: 253

IP mas agresiva: 45.33.32.156 (120 intentos)

Alertas generadas: 2 IPs superaron umbral de 50

Detecciones SQLi: 24 intentos identificados

Laboratorio 2: Reglas Wazuh
bash
# Copiar reglas al servidor Wazuh
scp local_rules_ssh.xml fray@192.168.56.10:/tmp/
scp local_rules_exfil.xml fray@192.168.56.10:/tmp/

# En servidor Wazuh
sudo cat /tmp/local_rules_ssh.xml >> /var/ossec/etc/rules/local_rules.xml
sudo cat /tmp/local_rules_exfil.xml >> /var/ossec/etc/rules/local_rules.xml
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager

# Simular ataque
sudo /tmp/simular_bruteforce.sh 45.33.32.156 15
Reglas implementadas:

ID 100010: 10 fallos en 60 segundos (Nivel 10)

ID 100011: 5 fallos en 30 segundos (Nivel 7)

ID 100012: 20 fallos en 120 segundos (Nivel 12)

Laboratorio 3: ML - Deteccion de Anomalias
bash
cd ~/examen-practico-kana/lab3

# Entrenar modelo
python3 ejecutar_lab3.py

# Probar prediccion
python3 predecir.py network_traffic.csv
python3 predecir.py nuevo_trafico.csv
Resultados del modelo:

Modelo: Isolation Forest

F1-Score: 0.6340

Umbral optimo: -0.092

Anomalias detectadas: 500 (5.00%)

Laboratorio 4: Dashboard SOC
bash
# Acceder a Kibana
https://192.168.56.10

# Credenciales
Usuario: admin
Contrasena: admin
Dashboard configurado:

4 visualizaciones integradas

Panel de texto con datos del autor

Filtro de tiempo: Ultimas 24 horas


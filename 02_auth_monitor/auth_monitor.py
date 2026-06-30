import os
from datetime import datetime

def record_security_log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {message}\n"
    print(f"[{timestamp}] {message}")
    with open("security_alerts.txt", "a", encoding="utf-8") as f:
        f.write(log_line)

record_security_log("=" * 50)
record_security_log("     STARTING AUTHENTICATION LOG MONITOR     ")
record_security_log("=" * 50)

log_file_path = "server_logs.txt"

# Verifica se o arquivo de log existe
if not os.path.exists(log_file_path):
    record_security_log(f"🚨 [ERROR] Log file '{log_file_path}' not found! Create the file first.")
    exit()

# Dicionário para contar falhas por IP
failed_attempts = {}
# Conjunto para registrar IPs já alertados
reported_ips = set()

record_security_log(f"[INFO] Analyzing '{log_file_path}' for brute force signatures...")

try:
    with open(log_file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            # Verifica se a linha indica uma falha de login
            if "LOGIN_FAILED" in line:
                try:
                    # Extrai o IP da linha de log
                    parts = line.split(" - ")
                    ip_part = parts[1].replace("IP: ", "").strip()
                    
                    # Incrementa o contador de falhas do IP
                    failed_attempts[ip_part] = failed_attempts.get(ip_part, 0) + 1
                    
                    # Se atingir 3 ou mais falhas, gera o alerta crítico
                    if failed_attempts[ip_part] >= 3 and ip_part not in reported_ips:
                        record_security_log(f"🚨 [CRITICAL ALERT] Brute Force Detected from IP: {ip_part}!")
                        record_security_log(f"⚠️ [ACTION REQUIRED] Add IP {ip_part} to the Firewall drop rules.")
                        reported_ips.add(ip_part)
                        
                except Exception as parse_error:
                    pass

    # Gera o relatório final se houver IPs bloqueados
    if reported_ips:
        with open("blocked_ips_report.txt", "w", encoding="utf-8") as report:
            report.write("=== SECURITY INCIDENT REPORT - BLOCKED IPS ===\n")
            report.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for ip in reported_ips:
                report.write(f"IP Address: {ip} | Total Failures: {failed_attempts[ip]} | Status: BLOCKED\n")
        record_security_log(f"✅ 'blocked_ips_report.txt' generated with {len(reported_ips)} offender(s).")
    else:
        record_security_log("✅ Analysis finished. No brute force activities detected.")

except Exception as e:
    record_security_log(f"🚨 [ERROR] Failed to read log file: {e}")

record_security_log("================ MONITORING PROCESS FINISHED ================")
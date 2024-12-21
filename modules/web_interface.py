from flask import Flask, render_template, jsonify, request
from threading import Thread
from modules.sniff import PacketAnalyzer
from modules.sip import NetworkScanner
import asyncio
import json
import time

app = Flask(__name__)

scanner = None
analyzer = None
loop = None

def run_async(coro):
    """Вспомогательная функция для запуска асинхронного кода в синхронном контексте"""
    global loop
    if loop is None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan_network', methods=['POST'])
def scan_network():
    if not scanner:
        return jsonify({"status": "error", "message": "Сканер не инициализирован"})
    
    data = request.json
    ip_range = data.get('ip_range', '')
    ports = data.get('ports', '')
    
    try:
        # Преобразуем порты из строки в список
        port_list = []
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
        
        # Запускаем сканирование через асинхронный вызов
        run_async(scanner.scan_ips(ip_range, port_list))
        
        # Читаем результаты из JSON файла
        try:
            with open('scan_results.json', 'r', encoding='utf-8') as f:
                results = json.load(f)
        except FileNotFoundError:
            return jsonify({"status": "error", "message": "Файл результатов не найден"})
            
        # Форматируем результаты для фронтенда
        formatted_results = []
        for result in results:
            if isinstance(result, dict):
                formatted_results.append({
                    "ip": result.get("ip", "Н/Д"),
                    "mac": result.get("mac", "Н/Д"),
                    "hostname": result.get("hostname", "Неизвестно"),
                    "status": "Активен",
                    "ports": [f"{p['port']} ({p['description']})" for p in result.get("open_ports", [])]
                })
        
        return jsonify({"status": "success", "data": formatted_results})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Ошибка сканирования: {str(e)}"})

@app.route('/api/analyze_traffic', methods=['POST'])
def analyze_traffic():
    if not analyzer:
        return jsonify({"status": "error", "message": "Анализатор не инициализирован"})
    
    try:
        data = request.json
        interface = data.get('interface', '')
        protocol = data.get('protocol', '')
        page = data.get('page', 1)  # Номер страницы
        per_page = data.get('per_page', 20)  # Пакетов на страницу
        
        if not interface:
            return jsonify({"status": "error", "message": "Интерфейс не выбран"})
        
        # Устанавливаем выбранный интерфейс
        analyzer.selected_interface = interface
        
        # Устанавливаем протокол для фильтрации
        if protocol.lower() == 'tcp':
            analyzer.protocol_filter = "tcp"
        elif protocol.lower() == 'udp':
            analyzer.protocol_filter = "udp"
        elif protocol.lower() == 'dns':
            analyzer.protocol_filter = "dns"
        elif protocol.lower() == 'all':
            analyzer.protocol_filter = None
        else:
            analyzer.protocol_filter = protocol
        
        # Запускаем сниффинг в отдельном потоке
        if not analyzer.running:
            analyzer.running = True
            sniff_thread = Thread(target=analyzer._start_capture)
            sniff_thread.daemon = True
            sniff_thread.start()
        
        # Даём время на запись в лог
        time.sleep(1)
        
        # Читаем результаты из лог-файла с пагинацией
        results = []
        try:
            with open('packet_sniffer.log', 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                
                for line in all_lines[start_idx:end_idx]:
                    try:
                        # Парсим строку лога в формате:
                        # PROTOCOL|SRC:PORT→DST:PORT|size:SIZE|flags:FLAGS
                        parts = line.strip().split(' - ')[1].split('|')
                        protocol = parts[0]
                        src_dst = parts[1].split('→')
                        size = parts[2].split(':')[1]
                        
                        packet = {
                            "protocol": protocol,
                            "src": src_dst[0],
                            "dst": src_dst[1],
                            "size": int(size),
                            "flags": parts[3].split(':')[1] if len(parts) > 3 else "Н/Д"
                        }
                        results.append(packet)
                    except (IndexError, ValueError):
                        continue
                        
            return jsonify({
                "status": "success", 
                "data": results,
                "has_more": len(all_lines) > end_idx  # Флаг наличия следующей страницы
            })
                
        except FileNotFoundError:
            return jsonify({"status": "error", "message": "Файл логов не найден"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Ошибка анализа: {str(e)}"})

@app.route('/api/get_interfaces', methods=['GET'])
def get_interfaces():
    if analyzer:
        interfaces = analyzer.get_available_interfaces()
        return jsonify({"status": "success", "data": interfaces})
    return jsonify({"status": "error", "message": "Анализатор не инициализирован"})

@app.route('/api/stop_analysis', methods=['POST'])
def stop_analysis():
    if analyzer and analyzer.running:
        analyzer.stop_analysis()
        return jsonify({"status": "success", "message": "Анализ трафика остановлен"})
    return jsonify({"status": "error", "message": "Анализ трафика не запущен"})

@app.route('/api/network_stats', methods=['GET'])
def get_network_stats():
    try:
        # Статистика из scan_results.json
        scan_stats = {"hosts": [], "total_ports": 0}
        try:
            with open('scan_results.json', 'r', encoding='utf-8') as f:
                scan_data = json.load(f)
                for host in scan_data:
                    if isinstance(host, dict):
                        scan_stats["hosts"].append({
                            "ip": host.get("ip"),
                            "ports": len(host.get("open_ports", []))
                        })
                        scan_stats["total_ports"] += len(host.get("open_ports", []))
        except FileNotFoundError:
            pass

        # Статистика из packet_sniffer.log
        traffic_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {},
            "hosts": {},
            "traffic_history": []
        }
        
        try:
            with open('packet_sniffer.log', 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Берём последние 100 записей для истории трафика
                recent_lines = lines[-100:]
                
                for line in lines:
                    try:
                        # Парсим строку лога
                        parts = line.strip().split(' - ')[1].split('|')
                        protocol = parts[0]
                        src_dst = parts[1].split('→')
                        size = int(parts[2].split(':')[1])
                        
                        # Обновляем общую статистику
                        traffic_stats["total_packets"] += 1
                        traffic_stats["total_bytes"] += size
                        
                        # Обновляем статистику по протоколам
                        traffic_stats["protocols"][protocol] = traffic_stats["protocols"].get(protocol, 0) + 1
                        
                        # Обновляем статистику по хостам
                        src_ip = src_dst[0].split(':')[0]
                        dst_ip = src_dst[1].split(':')[0]
                        traffic_stats["hosts"][src_ip] = traffic_stats["hosts"].get(src_ip, 0) + size
                        traffic_stats["hosts"][dst_ip] = traffic_stats["hosts"].get(dst_ip, 0) + size
                        
                    except (IndexError, ValueError):
                        continue
                
                # Формируем историю трафика
                packet_window = 10  # Группируем по 10 пакетов
                for i in range(0, len(recent_lines), packet_window):
                    window_lines = recent_lines[i:i+packet_window]
                    window_bytes = sum(
                        int(line.strip().split('|')[2].split(':')[1])
                        for line in window_lines
                        if len(line.strip().split('|')) > 2
                    )
                    traffic_stats["traffic_history"].append({
                        "time": f"-{len(recent_lines)-i}",
                        "bytes": window_bytes
                    })

        except FileNotFoundError:
            pass

        # Форматируем итоговую статистику
        return jsonify({
            "status": "success",
            "data": {
                "general": {
                    "total_packets": traffic_stats["total_packets"],
                    "total_bytes": traffic_stats["total_bytes"],
                    "active_hosts": len(scan_stats["hosts"]),
                    "avg_bandwidth": f"{(traffic_stats['total_bytes'] / max(1, traffic_stats['total_packets'])):.2f} байт/пакет"
                },
                "protocols": [
                    {"name": proto, "count": count}
                    for proto, count in sorted(
                        traffic_stats["protocols"].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]  # Top 10 протоколов
                ],
                "hosts": [
                    {"ip": ip, "bytes": bytes_count}
                    for ip, bytes_count in sorted(
                        traffic_stats["hosts"].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10]  # Top 10 хостов
                ],
                "traffic_history": traffic_stats["traffic_history"]
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Ошибка получения статистики: {str(e)}"})

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def start_web_interface(network_scanner, packet_analyzer):
    global scanner, analyzer
    scanner = network_scanner
    analyzer = packet_analyzer
    
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()

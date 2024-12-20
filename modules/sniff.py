import asyncio
import logging
from scapy.all import sniff, IP, TCP, UDP, DNS, Ether, conf, sr1
from datetime import datetime
from typing import Dict, List, Optional, Set
import netifaces
import threading
from termcolor import colored
import os
import platform
import ctypes

def is_admin():
    """Проверка прав администратора"""
    try:
        if platform.system().lower() == "windows":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

class PacketAnalyzer:
    def __init__(self):
        if not is_admin():
            raise PermissionError("Для захвата пакетов требуются права администратора")
        
        self.running = False
        self.packet_stats: Dict[str, Dict] = {}
        self.selected_interface = None
        self.protocol_filter = None
        self.capture_thread = None
        
        # Настройка логирования
        self.logger = logging.getLogger('packet_sniffer')
        self.logger.setLevel(logging.INFO)
        
        # Создаем файловый обработчик с немедленной записью
        fh = logging.FileHandler('packet_sniffer.log', mode='a')
        fh.setLevel(logging.INFO)
        
        # Создаем форматтер
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh.setFormatter(formatter)
        
        # Добавляем обработчик к логгеру
        self.logger.addHandler(fh)
        
        # Отключаем propagation чтобы избежать дублирования
        self.logger.propagate = False

    def get_available_interfaces(self) -> List[str]:
        """Получение списка доступных сетевых интерфейсов"""
        interfaces = netifaces.interfaces()
        valid_interfaces = []
        
        # Определяем операионную систему
        import platform
        is_windows = platform.system().lower() == "windows"
        
        for iface in interfaces:
            if is_windows:
                # На Windows используем все интерфейсы, кроме служебных
                if not (iface.startswith('{') or iface in ['lo', 'any']):
                    valid_interfaces.append(iface)
            else:
                # Для Linux оставляем текущую логику
                if iface.startswith(('eth', 'enp', 'wlan', 'wlp')):
                    valid_interfaces.append(iface)
        
        return valid_interfaces

    def select_interface(self):
        """Позволяет пользователю выбрать интерфейс для снифинга"""
        interfaces = self.get_available_interfaces()
        
        print(colored("\nДоступные интерфейсы:", "cyan"))
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {iface}")
            
        while True:
            try:
                choice = int(input("\nВыберите номер интерфейса: "))
                if 1 <= choice <= len(interfaces):
                    self.selected_interface = interfaces[choice-1]
                    print(colored(f"Выбран интерфейс: {self.selected_interface}", "green"))
                    break
                else:
                    print(colored("Неверный выбор. Попробуйте снова.", "red"))
            except ValueError:
                print(colored("Введите корректный номер.", "red"))

    def select_protocols(self):
        """Позволяет пользователю выбрать протоколы для анализа"""
        print(colored("\nДоступные протоколы:", "cyan"))
        print("1. Все протоколы")
        print("2. TCP")
        print("3. UDP")
        print("4. DNS")
        print("5. TCP + UDP")
        print("6. Пользовательский фильтр")
        
        while True:
            try:
                choice = int(input("\nВыберите протоколы (1-6): "))
                if choice == 1:
                    self.protocol_filter = None
                elif choice == 2:
                    self.protocol_filter = "tcp"
                elif choice == 3:
                    self.protocol_filter = "udp"
                elif choice == 4:
                    self.protocol_filter = "dns"
                elif choice == 5:
                    self.protocol_filter = "tcp or udp"
                elif choice == 6:
                    custom_filter = input("Введите BPF фильтр: ")
                    self.protocol_filter = custom_filter
                else:
                    print(colored("Неверный выбор. Попробуйте снова.", "red"))
                    continue
                break
            except ValueError:
                print(colored("Введите корректный номер.", "red"))

    def packet_callback(self, packet):
        """Обработка перехваченного пакета"""
        if not packet.haslayer(IP):
            return

        # Базовая информация о пакете
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Детальная информация о пакете
        packet_info = {
            "timestamp": timestamp,
            "size": size,
            "protocol": proto,
            "src": ip_src,
            "dst": ip_dst,
            "flags": [],
            "ack": None,
            "seq": None,
            "window": None,
            "port_src": None,
            "port_dst": None
        }

        # TCP-специфичная информация
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info.update({
                "port_src": tcp.sport,
                "port_dst": tcp.dport,
                "flags": [flag for flag in tcp.flags],
                "ack": tcp.ack,
                "seq": tcp.seq,
                "window": tcp.window
            })
            
        # UDP-специфичная информация
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info.update({
                "port_src": udp.sport,
                "port_dst": udp.dport
            })

        # DNS-специфичная информация
        if packet.haslayer(DNS):
            dns = packet[DNS]
            packet_info["dns_info"] = {
                "qname": dns.qd.qname.decode() if dns.qd else None,
                "qtype": dns.qd.qtype if dns.qd else None
            }

        # Вывод информации о пакете
        self._print_packet_info(packet_info)
        
        # Сохранение статистики
        if ip_src not in self.packet_stats:
            self.packet_stats[ip_src] = {"packets": 0, "bytes": 0}
        self.packet_stats[ip_src]["packets"] += 1
        self.packet_stats[ip_src]["bytes"] += size

    def _print_packet_info(self, info):
        """Форматированный вывод информации о пакете"""
        # Словарь протоколов и их цветов
        proto_map = {
            1: ("ICMP", "red"),
            6: ("TCP", "green"),
            17: ("UDP", "blue"),
            53: ("DNS", "yellow")
        }
        
        # Получаем имя протокола
        proto_name, color = proto_map.get(info["protocol"], ("UNKNOWN", "white"))
        
        # Формируем сообщение для лога
        log_message = (
            f"{proto_name}|{info['src']}:{info['port_src']}→{info['dst']}:{info['port_dst']}|"
            f"size:{info['size']}"
        )
        
        if info["flags"]:
            log_message += f"|flags:{','.join(info['flags'])}"
        if info.get("dns_info", {}).get("qname"):
            log_message += f"|dns:{info['dns_info']['qname']}"
        
        # Немедленная запись в лог
        self.logger.info(log_message)
        
        # Форматируем вывод только для терминала
        base_info = (
            f"\n{colored('╭─', 'white')} {info['timestamp']} "
            f"{colored(f'[{proto_name}]', color)} "
            f"\n{colored('├─', 'white')} {info['src']}:{info['port_src']} → {info['dst']}:{info['port_dst']}"
            f"\n{colored('├─', 'white')} Size: {info['size']} bytes"
        )
        
        # Добавляем специфичную информацию для протоколов
        details = []
        if info["flags"]:
            details.append(f"Flags: {','.join(info['flags'])}")
        if info["ack"]:
            details.append(f"ACK: {info['ack']}")
        if info["seq"]:
            details.append(f"SEQ: {info['seq']}")
        if info.get("dns_info", {}).get("qname"):
            details.append(f"DNS Query: {info['dns_info']['qname']}")
        
        # Форматируем детали
        if details:
            base_info += f"\n{colored('├─', 'white')} " + f"\n{colored('├─', 'white')} ".join(details)
        
        # Добавляем закрывающую линию
        base_info += f"\n{colored('╰─', 'white')}"
            
        print(base_info)

    async def start_analysis(self):
        """Запуск анализа пакетов"""
        if not self.selected_interface:
            self.select_interface()
        if self.protocol_filter is None:
            self.select_protocols()

        self.running = True
        print(colored(f"\nНачало захвата пакетов на интерфейсе {self.selected_interface}...", "yellow"))
        print(colored("Нажмите Ctrl+C для возврата в главное меню", "yellow"))

        # Запуск снифинга в отдельном потоке
        self.capture_thread = threading.Thread(
            target=self._start_capture
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()

        try:
            while self.running:
                await asyncio.sleep(0.1)  # Уменьшаем интервал для более быстрой реакции
        except (KeyboardInterrupt, asyncio.CancelledError):
            print(colored("\nЗавершение захвата пакетов...", "yellow"))
        finally:
            self.stop_analysis()
            print(colored("Захват пакетов остановлен", "green"))

    def _start_capture(self):
        """Запуск захвата пакетов"""
        try:
            # Настройка Scapy для Windows
            import platform
            if platform.system().lower() == "windows":
                conf.use_pcap = True
            
            sniff(
                iface=self.selected_interface,
                filter=self.protocol_filter,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            logging.error(f"Ошибка при захвате пакетов: {e}")
            self.running = False

    def stop_analysis(self):
        """Остановка анализа пакетов"""
        if self.running:
            self.running = False
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=2.0)  # Добавляем таймаут
                if self.capture_thread.is_alive():
                    logging.warning("Не удалось корректно остановить поток захвата")
            self._print_statistics()

    def _print_statistics(self):
        """Вывод статистики захвата"""
        print(colored("\nСтатистика захвата:", "cyan"))
        for ip, stats in self.packet_stats.items():
            print(f"IP: {ip}")
            print(f"  Пакетов: {stats['packets']}")
            print(f"  байт: {stats['bytes']}")

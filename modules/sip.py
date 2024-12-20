# Импортируем все нужные библиотеки для работы с сетью
import logging
import asyncio
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from ipaddress import ip_address, IPv4Address
from prettytable import PrettyTable
from concurrent.futures import ThreadPoolExecutor
from socket import gethostbyaddr, socket, AF_INET, SOCK_STREAM, timeout
from tqdm import tqdm
from termcolor import colored
from typing import List, Tuple, Optional
import json
import sys
import signal
from modules.config import NetworkConfig
from asyncio import Semaphore, create_task, gather
from functools import partial
import aiohttp
import aiodns
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table
import requests
from scapy.layers.inet import IP, ICMP
import platform
import ctypes
import os
import re
import subprocess


MAX_THREADS = 10
TIMEOUT = 1.5 

PORT_DESCRIPTIONS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP Proxy",
    3389: "RDP",
}

MAC_VENDORS = {}

def signal_handler(sig, frame):
    print(colored("\n[!] Сканирование прервано пользователем", "yellow"))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

class NetworkScanner:
    """
    Сканер сети. Выполняет разведку хостов, портов и сервисов.
    Работает асинхронно, что делает его менее бесполезным.
    """

    def __init__(self):
        self.config = NetworkConfig()
        self.semaphore = Semaphore(self.config.get('MAX_CONCURRENT_SCANS', 10))
        self.dns_cache = {}  # Кэш DNS-записей для оптимизации повторных запросов
        self.session = None
        self.dns_resolver = None
        self.console = Console()
        
        # Определяем операционную систему
        self.is_windows = platform.system().lower() == "windows"
        
        # Проверка прав администратора
        if not self._check_admin():
            raise PermissionError("Требуются права администратора для сканирования сети")
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        self.dns_resolver = aiodns.DNSResolver()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def scan_port(self, ip: str, port: int) -> Optional[Tuple[int, str]]:
        """
        Сканирует отдельный порт на наличие открытых сервисов.
        Возвращает кортеж (порт, описание) если порт открыт, иначе None
        """
        try:
            conn = socket(AF_INET, SOCK_STREAM)
            conn.settimeout(self.config.get('PORT_SCAN_TIMEOUT', 2.0))
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: conn.connect_ex((ip, port))
            )
            conn.close()
            if result == 0:
                return (port, PORT_DESCRIPTIONS.get(port, "Unknown"))
            return None
        except Exception as e:
            logging.debug(f"Port {port} scan failed: {e}")
            return None

    async def get_hostname(self, ip: str) -> str:
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: gethostbyaddr(ip)[0]
            )
            self.dns_cache[ip] = result
            return result
        except Exception:
            return "Unknown"

    async def handle_ip_scanning(self):
        try:
            self.console.print(Panel(
                "[bold cyan]Network Scanner v1.0[/]\n[dim]cuz i am a hacker[/]",
                box=box.DOUBLE,
                style="cyan"
            ))
            
            ip_input = input("Введите IP-адрес или диапазон (например, 192.168.0.1 или 192.168.0.1-20): ").strip()
            if not self.validate_ip_range(ip_input):
                print(colored("[!] Некорректный формат IP. Попробуйте ещё раз.", "red"))
                return

            menu = Table(show_header=True, box=box.SIMPLE)
            menu.add_column("Выбор", style="cyan")
            menu.add_column("Описание", style="green")
            menu.add_column("Формат", style="yellow")
            menu.add_row("0", "Только живые хосты", "Без сканирования портов")
            menu.add_row("1", "Все порты", "1-65535")
            menu.add_row("2", "Конкретные порты", "22,80,443")
            menu.add_row("3", "Диапазон портов", "20-1000")
            self.console.print(Panel(menu, title="Выберите тип сканирования", style="bold cyan"))

            port_choice = input("Ваш выбор (0-3): ").strip()

            try:
                if port_choice == '0':
                    ports = []
                elif port_choice == '1':
                    ports = range(1, 65536)
                elif port_choice == '2':
                    port_input = input("Введите порты через запятую (например, 22,80,443): ")
                    ports = [int(port.strip()) for port in port_input.split(',') 
                            if port.strip().isdigit() and 0 < int(port.strip()) <= 65535]
                    if not ports and port_choice != '0':
                        raise ValueError("Не указаны корректные порты")
                elif port_choice == '3':
                    start_port = int(input("Введите начальный порт: "))
                    end_port = int(input("Введите конечный порт: "))
                    if not (0 < start_port < end_port <= 65535):
                        raise ValueError("Некорректный диапазон портов")
                    ports = range(start_port, end_port + 1)
                else:
                    raise ValueError("Неверный выбор")
            except ValueError as e:
                print(colored(f"[!] Ошибка: {e}", "red"))
                return

            await self.scan_ips(ip_input, list(ports))

        except Exception as e:
            print(colored(f"[!] Произошла ошибка: {e}", "red"))

    def validate_ip_range(self, ip_range: str) -> bool:
        """
        Проверяет корректность введенного диапазона IP-адресов.
        Поддерживает форматы: одиночный IP или диапазон (192.168.0.1-20)
        """
        try:
            if "-" in ip_range:
                base_ip, end = ip_range.split("-")
                IPv4Address(base_ip)
                end_num = int(end)
                if not 0 <= end_num <= 255:
                    return False
                start_num = int(base_ip.split(".")[-1])
                if end_num < start_num:
                    return False
            else:
                IPv4Address(ip_range)
            return True
        except Exception:
            return False

    def generate_ip_range(self, ip_range: str) -> List[str]:
        if "-" in ip_range:
            base_ip, end = ip_range.split("-")
            base_prefix = base_ip.rsplit(".", 1)[0]
            start = int(base_ip.split(".")[-1])
            end = int(end)
            return [f"{base_prefix}.{i}" for i in range(start, end + 1)]
        return [ip_range]

    async def scan_ip_alive(self, ip: str) -> Optional[str]:
        """Проверка доступности IP-адреса"""
        try:
            if self.is_windows:
                # На Windows используем ping через ICMP
                ping_packet = IP(dst=ip)/ICMP()
                reply = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: sr1(ping_packet, timeout=1, verbose=False)
                )
                return ip if reply else None
            else:
                # На Linux используем ARP
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: srp(packet, timeout=1, verbose=False)
                )
                return ip if result and result[0] else None
        except Exception as e:
            logging.debug(f"Error scanning {ip}: {e}")
            return None

    async def scan_mac_address(self, ip: str) -> Optional[str]:
        """Получение MAC-адреса"""
        try:
            if self.is_windows:
                # На Windows используем ARP-таблицу
                output = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: subprocess.check_output(['arp', '-a', ip], 
                                                 stderr=subprocess.DEVNULL).decode()
                )
                # Извлекаем MAC из вывода ARP
                for line in output.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                        if mac_match:
                            return mac_match.group(0)
                return None
            else:
                # На Linux используем ARP-запрос
                arp = ARP(pdst=ip)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: srp(packet, timeout=1, verbose=False)
                )
                if result and result[0]:
                    return result[0][0][1].hwsrc
                return None
        except Exception as e:
            logging.debug(f"Error getting MAC for {ip}: {e}")
            return None

    async def scan_ports(self, ip: str, ports: List[int]) -> List[Tuple[int, str]]:
        open_ports = []
        async with self.semaphore:
            for port in ports:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.config.get('PORT_SCAN_TIMEOUT', 1.0)
                    )
                    open_ports.append((port, PORT_DESCRIPTIONS.get(port, "Unknown")))
                    writer.close()
                    await writer.wait_closed()
                except (asyncio.TimeoutError, ConnectionRefusedError):
                    continue
                except Exception as e:
                    logging.debug(f"Error scanning {ip}:{port} - {str(e)}")
        return open_ports

    async def scan_ips(self, ip_range: str, ports: List[int]):
        """
        Основной метод сканирования. Выполняет:
        1. Поиск живых хостов
        2. Определение имен хостов(hostname)
        3. Получение MAC-адресов
        4. Сканирование портов (если указаны)
        """
        try:
            ip_list = self.generate_ip_range(ip_range)
            results = []
            start_time = time.time()
            alive_hosts = []
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TimeElapsedColumn(),
            ) as progress:
                hosts_task = progress.add_task("[cyan]Phase 1: Checking alive hosts...", total=len(ip_list))
                
                tasks = []
                for ip in ip_list:
                    tasks.append(self.scan_ip_alive(ip))
                
                alive_results = await asyncio.gather(*tasks)
                for ip, is_alive in zip(ip_list, alive_results):
                    if is_alive:
                        alive_hosts.append(ip)
                    progress.update(hosts_task, advance=1)

                if not alive_hosts:
                    print(colored("\n[!] No alive hosts found", "yellow"))
                    return

                hostname_task = progress.add_task("[yellow]Phase 2: Resolving hostnames...", total=len(alive_hosts))
                hostnames = {}
                for ip in alive_hosts:
                    hostnames[ip] = await self.get_hostname(ip)
                    progress.update(hostname_task, advance=1)

                mac_task = progress.add_task("[green]Phase 3: Getting MAC addresses...", total=len(alive_hosts))
                macs = {}
                for ip in alive_hosts:
                    macs[ip] = await self.scan_mac_address(ip)
                    progress.update(mac_task, advance=1)

                if ports:  # Добавляем проверку наличия портов для сканирования
                    ports_task = progress.add_task("[red]Phase 4: Scanning ports...", total=len(alive_hosts))
                    for ip in alive_hosts:
                        if macs[ip]:  
                            elapsed_time = time.time() - start_time
                            open_ports = await self.scan_ports(ip, ports)
                            results.append({
                                'ip': ip,
                                'mac': macs[ip],
                                'hostname': hostnames[ip],
                                'ports': open_ports,
                                'scan_time': f"{elapsed_time:.2f}s"
                            })
                        progress.update(ports_task, advance=1)
                else:
                    # Если порты не указаны, добавляем только информацию о хостах
                    for ip in alive_hosts:
                        elapsed_time = time.time() - start_time
                        results.append({
                            'ip': ip,
                            'mac': macs[ip],
                            'hostname': hostnames[ip],
                            'ports': [],
                            'scan_time': f"{elapsed_time:.2f}s"
                        })

            results_table = Table(show_header=True, box=box.HEAVY_EDGE)
            results_table.add_column("IP", style="cyan")
            results_table.add_column("MAC", style="green")
            results_table.add_column("Hostname", style="yellow")
            results_table.add_column("Open Ports", style="red")
            results_table.add_column("Scan Time", style="blue")

            for result in results:
                ports_str = "\n".join(f"{port} ({desc})" for port, desc in result['ports']) if result['ports'] else "None"
                results_table.add_row(
                    result['ip'],
                    result['mac'] or "Unknown",
                    result['hostname'] or "Unknown",
                    ports_str,
                    result['scan_time']
                )

            total_time = time.time() - start_time
            self.console.print("\n")
            self.console.print(Panel(
                results_table, 
                title=f"[bold]Scan Results (Total time: {total_time:.2f}s)[/]",
                border_style="blue"
            ))
            
            await self.export_results("scan_results.json", results)
            print(colored(f"\n[+] Total hosts processed: {len(results)}", "green"))

        except Exception as e:
            print(colored(f"[!] Scan error: {e}", "red"))

    async def export_results(self, filename: str, results: List[dict]):
        """
        Сохраняет результаты сканирования в JSON-файл.
        Структурирует данные для последующего анализа
        """
        try:
            formatted_results = [
                {
                    "ip": result["ip"],
                    "mac": result["mac"],
                    "hostname": result["hostname"],
                    "open_ports": [{"port": port, "description": desc} for port, desc in result["ports"]],
                    "scan_time": result["scan_time"]
                }
                for result in results
            ]
            
            async with asyncio.Lock():
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(formatted_results, f, ensure_ascii=False, indent=4)
            
            print(colored(f"[+] Результаты сохранены в {filename}", "green"))
        except Exception as e:
            print(colored(f"[!] Ошибка при сохранении результатов: {e}", "red"))

    def hacker_print(self, text, delay=0.02):
        for char in text:
            sys.stdout.write(colored(char, 'green'))
            sys.stdout.flush()
            time.sleep(delay)
        print()

    def _check_admin(self) -> bool:
        """Проверка прав администратора"""
        try:
            if self.is_windows:
                return ctypes.windll.shell32.IsUserAnAdmin()
            return os.geteuid() == 0
        except:
            return False

if __name__ == "__main__":
    try:
        asyncio.run(handle_ip_scanning())
    except KeyboardInterrupt:
        print(colored("\n[!] Сканирование прервано пользователем", "yellow"))
    except Exception as e:
        print(colored(f"[!] Критическая ошибка: {e}", "red"))

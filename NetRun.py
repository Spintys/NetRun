import asyncio
import logging
import os
from datetime import datetime
from typing import Optional
from termcolor import colored
from modules.config import NetworkConfig
from modules.sniff import PacketAnalyzer
from modules.sip import NetworkScanner
import threading
import platform
from scapy.all import conf

class NetRun:
    """
    Главный класс программы. Управляет всем этим цирком
    """

    def __init__(self):
        self.config = NetworkConfig()
        self.agreement_log = "user_agreement_log.txt"  # Файл для юридической защиты(я не юрист)
        self.scanner: Optional[NetworkScanner] = None
        self.analyzer: Optional[PacketAnalyzer] = None
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler('netrun.log'),
                logging.StreamHandler()
            ]
        )
        
    async def initialize(self):
        """
        Инициализация компонентов. 
        Потому что кто-то решил, что асинронность - это круто(я тоже)
        """
        try:
            if platform.system().lower() == "windows":
                conf.use_pcap = True
            
            self.scanner = NetworkScanner()
            self.analyzer = PacketAnalyzer()
            async with self.scanner:
                await self.scanner.__aenter__()
            
        except Exception as e:
            logging.error(f"Error during initialization: {e}")
            raise
            
    async def cleanup(self):
        """
        Очистка ресурсов. 
        На случай, если что-то пойдет не так (а оно пойдет)
        """
        if self.scanner:
            try:
                await self.scanner.__aexit__(None, None, None)
                if self.analyzer:
                    await self.analyzer.close_session()
                    await asyncio.sleep(0.1)
            except Exception as e:
                logging.error(f"Error during cleanup: {e}")

    def _verify_user_agreement(self) -> bool:
        """
        Проверяет, согласился ли пользователь с условиями.
        Защита от юристов, не более того
        """
        if os.path.exists(self.agreement_log):
            with open(self.agreement_log, "r") as log:
                return any("Пользователь согласился с условиями" in line for line in log)
        return False

    def _log_agreement(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.agreement_log, "a") as log:
            log.write(f"{timestamp} - Пользователь согласился с условиями.\n")

    def show_agreement(self) -> bool:
        """
        Показывает пользовательское соглашение.
        Потому что без этого нельзя, да
        """
        agreement = """
        **Пользовательское соглашение**
        
        Используя это ПО, вы соглашаетесь:
        1. Не использовать его для противозаконной деятельности
        2. Не сканирнвать сети без разрешения владельца
        3. Не использовать результаты для нанесения вреда
        
        Полный текст пользовательского соглашения: https://github.com/Spintys/NetRun/blob/main/User%20Agreement.md или в файле User Agreement.md
        """
        print(colored(agreement, "yellow"))
        
        consent = input("\nСогласны с условиями? (да/нет): ").strip().lower()
        if consent != "да":
            logging.warning("Пользователь отказался от соглашения")
            return False
            
        self._log_agreement()
        return True

    async def menu(self):
        """
        Главное меню программы.
        Бесконечный цикл выбора опций, пока пользователь не сдастс
        """
        while True:
            try:
                print(colored("\nNetRun - Главное меню:", "cyan"))
                print("1. Сканирование сети")
                print("2. Анализ трафика")
                print("3. Настройк")
                print("0. Выход")
                
                choice = input("\nВыберите опцию: ").strip()
                
                if choice == "1":
                    await self.scanner.handle_ip_scanning()
                elif choice == "2":
                    await self.analyzer.start_analysis()
                elif choice == "3":
                    self.show_settings()
                elif choice == "0":
                    print(colored("\nЗавершение работы...", "yellow"))
                    break
                else:
                    print(colored("Неверный выбор. Попробуйте снова.", "red"))
                    
            except KeyboardInterrupt:
                print(colored("\nПринудительное завершение...", "yellow"))
                break
            except Exception as e:
                logging.error(f"Критическая ошибка: {e}")
                print(colored(f"\nПроизошла ошибка: {e}", "red"))

    def show_logo(self):
        """
        Выводит ASCII-арт логотип.
        Потому что каждой программе нужен бесполезный логотип(даже windows(windows ужасная ос(I use arch btw)))
        """
        logo = """
        ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗███╗   ██╗
        ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗  ██║
        ██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██╔██╗ ██║
        ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║   ██║██║╚██╗██║
        ██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║
        ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        """
        print(colored(logo, "cyan"))
        print(colored("NetRun v1.0", "yellow"))
        print(colored("Created by Spinty", "green"))

    def show_settings(self):
        """
        Меню настроек. 
        Позволяет пользователям портить работу программы по своему вкусу
        """
        while True:
            print(colored("\nНастройки:", "cyan"))
            print(f"1. Таймаут сканирования (сек): {self.config.TIMEOUT}")
            print(f"2. Макс. количество потоков: {self.config.MAX_CONCURRENT_SCANS}")
            print(f"3. Порог обнаружения DDoS (пакетов/сек): {self.config.DDOS_THRESHOLDS['CRITICAL'][60]}")
            print(f"4. Интервал очистки кэша (сек): {self.config.CACHE_CLEANUP_INTERVAL}")
            print("0. Назад")

            choice = input("\nВыберите па��аметр для изменения: ").strip()

            try:
                if choice == "1":
                    new_value = float(input("Введите новое значение таймаута (сек): "))
                    self.config.TIMEOUT = new_value
                elif choice == "2":
                    new_value = int(input("Введите максимальное количество потоков: "))
                    self.config.MAX_CONCURRENT_SCANS = new_value
                elif choice == "3":
                    new_value = int(input("Введите порог DDoS (пакетов/сек): "))
                    self.config.DDOS_THRESHOLDS['CRITICAL'][60] = new_value
                elif choice == "4":
                    new_value = int(input("Введите интервал очистки кэша (сек): "))
                    self.config.CACHE_CLEANUP_INTERVAL = new_value
                elif choice == "0":
                    break
                else:
                    print(colored("Неверный выбор. Попробуйте снова.", "red"))
                    continue

                print(colored("Настройки успешно обновлены!", "green"))
                
            except ValueError:
                print(colored("Ошибка: Введите корректное числовое значение", "red"))

async def main():
    """
    Точка входа в программу.
    Собирает все компоненты вместе и надеется на лучшее
    """
    netrun = NetRun()
    
    netrun.show_logo()
    
    if not netrun._verify_user_agreement():
        if not netrun.show_agreement():
            return
    
    try:
        await netrun.initialize()
        
        # Start web interface in a separate thread
        
        await netrun.menu()
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        await netrun.cleanup()
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(colored("\nПрограмма завершена ользователем", "yellow"))
    except Exception as e:
        logging.critical(f"Необработанная ошибка: {e}")
        print(colored(f"\nКритическая ошибка: {e}", "red"))

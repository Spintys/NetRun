from dataclasses import dataclass, field
from typing import Dict, List

class NetworkConfig:
    def __init__(self):
        # Базовые настройки
        self.TIMEOUT = 1.5
        self.MAX_CONCURRENT_SCANS = 10
        self.PACKET_BUFFER_SIZE = 1000
        self.CACHE_CLEANUP_INTERVAL = 300
        
        # Настройки для анализа DDoS
        self.DDOS_TIME_WINDOWS = [60, 300, 900]  # 1 мин, 5 мин, 15 мин
        self.DDOS_THRESHOLDS = {
            'CRITICAL': {60: 1000, 300: 3000, 900: 5000},
            'WARNING': {60: 500, 300: 1500, 900: 2500}
        }
        
        # Настройки для сессий и сканирования портов
        self.SESSION_TIMEOUT = 300  # 5 минут
        self.PORT_SCAN_THRESHOLD = 100  # Количество попыток сканирования портов
        self.ALERT_COOLDOWN = 60  # Минимальный интервал между повторными алертами
        
        # Настройки для очистки кэша
        self.CACHE_CLEANUP_INTERVAL = 300  # 5 минут
        
        # Настройки для веб-интерфейса
        self.WEB_HOST = "localhost"
        self.WEB_PORT = 8080
        
        # Настройки для логирования
        self.LOG_LEVEL = "INFO"
        self.LOG_FILE = "netrun.log"

    def get(self, key, default=None):
        """
        Безопасное получение значения конфигурации
        """
        return getattr(self, key, default)

    def set(self, key, value):
        """
        Установка значения конфигурации
        """
        setattr(self, key, value)

    def update(self, config_dict):
        """
        Массовое обновление конфигурации из словаря
        """
        for key, value in config_dict.items():
            self.set(key, value)
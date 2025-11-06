import json
import os
from typing import List, Dict, Any
from pydantic import BaseModel

class APIConfig(BaseModel):
    title: str
    version: str
    description: str
    host: str
    port: int
    reload: bool
    workers: int
    cors_origins: List[str]
    cors_allow_credentials: bool
    cors_allow_methods: List[str]
    cors_allow_headers: List[str]

class ScanningConfig(BaseModel):
    allowed_extensions: List[str]
    max_file_size: int
    default_scan_pickle: bool
    default_scan_saved_model: bool
    default_scan_h5: bool
    default_scan_onnx: bool
    scan_timeout: int

class PathsConfig(BaseModel):
    upload_dir: str
    scan_results_dir: str
    logs_dir: str
    config_dir: str

class LoggingConfig(BaseModel):
    level: str
    format: str
    max_file_size: int
    backup_count: int

class SecurityConfig(BaseModel):
    enable_rate_limiting: bool
    max_requests_per_minute: int
    api_key_required: bool
    allowed_file_types: List[str]

class Settings(BaseModel):
    api: APIConfig
    scanning: ScanningConfig
    paths: PathsConfig
    logging: LoggingConfig
    security: SecurityConfig

class ConfigManager:
    """Менеджер конфигураций"""
    
    def __init__(self, config_path: str = "config/settings.json"):
        self.config_path = config_path
        self.settings = self._load_config()
        self._create_directories()
    
    def _load_config(self) -> Settings:
        """Загружает конфигурацию из JSON файла"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            return Settings(**config_data)
        
        except FileNotFoundError:
            raise Exception(f"Конфигурационный файл не найден: {self.config_path}")
        except json.JSONDecodeError as e:
            raise Exception(f"Ошибка парсинга JSON: {e}")
        except Exception as e:
            raise Exception(f"Ошибка загрузки конфигурации: {e}")
    
    def _create_directories(self):
        """Создает необходимые директории"""
        directories = [
            self.settings.paths.upload_dir,
            self.settings.paths.scan_results_dir,
            self.settings.paths.logs_dir,
            self.settings.paths.config_dir
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get_config(self) -> Settings:
        """Возвращает текущую конфигурацию"""
        return self.settings
    
    def reload_config(self):
        """Перезагружает конфигурацию"""
        self.settings = self._load_config()
    
    def save_config(self, new_config: Dict[str, Any]):
        """Сохраняет новую конфигурацию"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(new_config, f, indent=2, ensure_ascii=False)
            
            self.reload_config()
            return True
        
        except Exception as e:
            raise Exception(f"Ошибка сохранения конфигурации: {e}")
    
    def get_allowed_extensions(self) -> List[str]:
        """Возвращает список разрешенных расширений"""
        return self.settings.scanning.allowed_extensions
    
    def get_max_file_size(self) -> int:
        """Возвращает максимальный размер файла"""
        return self.settings.scanning.max_file_size

# Глобальный экземпляр менеджера конфигураций
config_manager = ConfigManager()
settings = config_manager.get_config()
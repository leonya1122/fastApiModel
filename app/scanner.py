import asyncio
import uuid
from typing import Dict, List, Optional
from modelscan.modelscan import ModelScan
from models import SecurityIssue, SeverityLevel, ScanStatus, ScanResponse
from config import config_manager
import json
import os
from datetime import datetime

class ModelScanner:
    """Класс для сканирования моделей ML с конфигурацией из JSON"""
    
    def __init__(self):
        self.scanner = self._initialize_scanner()
        self.active_scans: Dict[str, Dict] = {}
        self.settings = config_manager.get_config()
    
    def _initialize_scanner(self) -> ModelScan:
        """Инициализирует сканер с настройками из конфигурации"""
        # ModelScan может принимать параметры инициализации
        # В текущей версии может не поддерживать все параметры, но оставляем для будущего
        scanner = ModelScan()
        return scanner
    
    def _get_scan_settings(self) -> Dict:
        """Возвращает настройки сканирования из конфигурации"""
        return {
            "pickle": self.settings.modelscan.enable_pickle_scan,
            "saved_model": self.settings.modelscan.enable_saved_model_scan,
            "h5": self.settings.modelscan.enable_h5_scan,
            "onnx": self.settings.modelscan.enable_onnx_scan,
            "scan_depth": self.settings.modelscan.scan_depth,
            "max_file_size": self.settings.modelscan.max_file_size
        }
    
    def _convert_severity(self, severity: str) -> SeverityLevel:
        """Конвертирует severity из ModelScan в наш формат"""
        severity_map = {
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL
        }
        return severity_map.get(severity.lower(), SeverityLevel.MEDIUM)
    
    def _parse_issues(self, scan_results: Dict) -> List[SecurityIssue]:
        """Парсит результаты сканирования в список проблем"""
        issues = []
        
        if not scan_results or "issues" not in scan_results:
            return issues
        
        for issue in scan_results["issues"]:
            security_issue = SecurityIssue(
                issue_type=issue.get("type", "unknown"),
                description=issue.get("description", ""),
                severity=self._convert_severity(issue.get("severity", "medium")),
                location=issue.get("location"),
                details=issue.get("details", {})
            )
            issues.append(security_issue)
        
        return issues
    
    async def scan_file(self, file_path: str, scan_id: str) -> ScanResponse:
        """Асинхронно сканирует файл"""
        try:
            # Обновляем статус сканирования
            self.active_scans[scan_id] = {
                "status": ScanStatus.SCANNING,
                "file_path": file_path,
                "start_time": datetime.now(),
                "settings": self._get_scan_settings()
            }
            
            # Запускаем сканирование в отдельном потоке с таймаутом
            loop = asyncio.get_event_loop()
            scan_results = await asyncio.wait_for(
                loop.run_in_executor(None, self.scanner.scan, file_path),
                timeout=self.settings.scanning.scan_timeout
            )
            
            # Парсим результаты
            issues = self._parse_issues(scan_results)
            
            # Создаем ответ
            response = ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                file_path=file_path,
                issues=issues,
                scan_summary={
                    "total_issues": len(issues),
                    "high_severity_issues": len([i for i in issues if i.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]]),
                    "scan_time": str(datetime.now()),
                    "scan_settings": self._get_scan_settings()
                },
                timestamp=str(datetime.now())
            )
            
            # Сохраняем результаты
            await self._save_results(scan_id, response)
            
            # Обновляем статус
            self.active_scans[scan_id]["status"] = ScanStatus.COMPLETED
            self.active_scans[scan_id]["end_time"] = datetime.now()
            self.active_scans[scan_id]["results"] = response.dict()
            
            return response
            
        except asyncio.TimeoutError:
            error_msg = f"Сканирование превысило лимит времени ({self.settings.scanning.scan_timeout} секунд)"
            self.active_scans[scan_id]["status"] = ScanStatus.FAILED
            self.active_scans[scan_id]["error"] = error_msg
            raise Exception(error_msg)
            
        except Exception as e:
            # Обновляем статус при ошибке
            self.active_scans[scan_id]["status"] = ScanStatus.FAILED
            self.active_scans[scan_id]["error"] = str(e)
            raise e
    
    async def _save_results(self, scan_id: str, response: ScanResponse):
        """Сохраняет результаты сканирования"""
        result_file = os.path.join(
            self.settings.paths.scan_results_dir, 
            f"{scan_id}.json"
        )
        
        async with await asyncio.to_thread(open, result_file, 'w') as f:
            json_str = json.dumps(
                response.dict(), 
                indent=2, 
                ensure_ascii=False, 
                default=str
            )
            await f.write(json_str)
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Возвращает статус сканирования"""
        return self.active_scans.get(scan_id)

# Глобальный экземпляр сканера
scanner = ModelScanner()
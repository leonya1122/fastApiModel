import asyncio
from typing import Dict, List, Optional
from modelscan.modelscan import ModelScan
from models import SecurityIssue, SeverityLevel, ScanStatus, ScanResponse
from config import config_manager
import json
import os
from datetime import datetime
from modelscan.settings import DEFAULT_SETTINGS

"""Класс для сканирования моделей ML"""
class ModelScanner:

    def __init__(self):
        self.settings = config_manager.get_config()
        
        #для изменения настроек сканирования
        #custom_settings = DEFAULT_SETTINGS.copy()
        #custom_settings["scanners"] = ...

        self.scanner = ModelScan()
        self.active_scans: Dict[str, Dict] = {}
    
    """Конвертирует severity из ModelScan в наш формат"""
    def _convert_severity(self, severity: str) -> SeverityLevel:
        
        severity_map = {
            "low": SeverityLevel.LOW,
            "medium": SeverityLevel.MEDIUM,
            "high": SeverityLevel.HIGH,
            "critical": SeverityLevel.CRITICAL
        }
        return severity_map.get(severity.lower(), SeverityLevel.MEDIUM)
    
    """Парсит результаты сканирования в список проблем"""
    def _parse_issues(self, scan_results: Dict) -> List[SecurityIssue]:
        
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
    
    """Асинхронно сканирует файл"""
    async def scan_file(self, file_path: str, scan_id: str) -> ScanResponse:
        try:
            # Обновляем статус сканирования
            self.active_scans[scan_id] = {
                "status": ScanStatus.SCANNING,
                "file_path": file_path,
                "start_time": datetime.now(),
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
                    "scan_time": str(datetime.now())
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
    
    """Сохраняет результаты сканирования"""
    async def _save_results(self, scan_id: str, response: ScanResponse):
        result_file = os.path.join(
            self.settings.paths.scan_results_dir, 
            f"{scan_id}.json"
        )
        def write_results():
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(
                    response.dict(), 
                    f, 
                    indent=2, 
                    ensure_ascii=False, 
                    default=str
                )
        
        await asyncio.get_event_loop().run_in_executor(None, write_results)
    
    """Возвращает статус сканирования"""
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        return self.active_scans.get(scan_id)

# Глобальный экземпляр сканера
scanner = ModelScanner()
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
class ModelScanner(ModelScan):

    def __init__(self,settings=DEFAULT_SETTINGS):
        super().__init__(settings=settings)
        self.project_settings = config_manager.get_config()
        #для изменения настроек сканирования
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
                loop.run_in_executor(None, super().scan, file_path),
                timeout=self.project_settings.scanning.scan_timeout
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
            error_msg = f"Сканирование превысило лимит времени ({self.project_settings.scanning.scan_timeout} секунд)"
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
            self.project_settings.paths.scan_results_dir, 
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
custom_settings = DEFAULT_SETTINGS.copy()
#custom_settings['scanners']['modelscan.scanners.SavedModelLambdaDetectScan']['enabled'] = False
#custom_settings['scanners']['modelscan.scanners.SavedModelTensorflowOpScan']['enabled'] = False


scanner = ModelScanner(settings=custom_settings)


#все настройки сканирования
'''DEFAULT_SETTINGS = {
    "modelscan_version": __version__,
    "supported_zip_extensions": [".zip", ".npz"],
    "scanners": {
        "modelscan.scanners.H5LambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".h5"],
        },
        "modelscan.scanners.KerasLambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".keras"],
        },
        "modelscan.scanners.SavedModelLambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".pb"],
            "unsafe_keras_operators": {
                "Lambda": "MEDIUM",
            },
        },
        "modelscan.scanners.SavedModelTensorflowOpScan": {
            "enabled": True,
            "supported_extensions": [".pb"],
            "unsafe_tf_operators": {
                "ReadFile": "HIGH",
                "WriteFile": "HIGH",
            },
        },
        "modelscan.scanners.NumpyUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [".npy"],
        },
        "modelscan.scanners.PickleUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [
                ".pkl",
                ".pickle",
                ".joblib",
                ".dill",
                ".dat",
                ".data",
            ],
        },
        "modelscan.scanners.PyTorchUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [".bin", ".pt", ".pth", ".ckpt"],
        },
    },
    "middlewares": {
        "modelscan.middlewares.FormatViaExtensionMiddleware": {
            "formats": {
                SupportedModelFormats.TENSORFLOW: [".pb"],
                SupportedModelFormats.KERAS_H5: [".h5"],
                SupportedModelFormats.KERAS: [".keras"],
                SupportedModelFormats.NUMPY: [".npy"],
                SupportedModelFormats.PYTORCH: [".bin", ".pt", ".pth", ".ckpt"],
                SupportedModelFormats.PICKLE: [
                    ".pkl",
                    ".pickle",
                    ".joblib",
                    ".dill",
                    ".dat",
                    ".data",
                ],
            }
        }
    },
    "unsafe_globals": {
        "CRITICAL": {
            "__builtin__": [
                "eval",
                "compile",
                "getattr",
                "apply",
                "exec",
                "open",
                "breakpoint",
                "__import__",
            ],  # Pickle versions 0, 1, 2 have those function under '__builtin__'
            "builtins": [
                "eval",
                "compile",
                "getattr",
                "apply",
                "exec",
                "open",
                "breakpoint",
                "__import__",
            ],  # Pickle versions 3, 4 have those function under 'builtins'
            "runpy": "*",
            "os": "*",
            "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
            "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
            "socket": "*",
            "subprocess": "*",
            "sys": "*",
            "operator": [
                "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
            ],
            "pty": "*",
            "pickle": "*",
            "_pickle": "*",
            "bdb": "*",
            "pdb": "*",
            "shutil": "*",
            "asyncio": "*",
        },
        "HIGH": {
            "webbrowser": "*",  # Includes webbrowser.open()
            "httplib": "*",  # Includes http.client.HTTPSConnection()
            "requests.api": "*",
            "aiohttp.client": "*",
        },
        "MEDIUM": {},
        "LOW": {},
    },
    "reporting": {
        "module": "modelscan.reports.ConsoleReport",
        "settings": {},
    },  # JSON reporting can be configured by changing "module" to "modelscan.reports.JSONReport" and adding an optional "output_file" field. For custom reporting modules, change "module" to the module name and add the applicable settings fields
}'''
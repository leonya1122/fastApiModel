from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityIssue(BaseModel):
    issue_type: str = Field(..., description="Тип проблемы")
    description: str = Field(..., description="Описание проблемы")
    severity: SeverityLevel = Field(..., description="Уровень серьезности")
    location: Optional[str] = Field(None, description="Местоположение в файле")
    details: Optional[Dict[str, Any]] = Field(None, description="Детальная информация")

class ScanRequest(BaseModel):
    file_path: Optional[str] = Field(None, description="Путь к файлу для сканирования")
    scan_pickle: bool = Field(True, description="Сканировать pickle файлы")
    scan_saved_model: bool = Field(True, description="Сканировать SavedModel")
    scan_h5: bool = Field(True, description="Сканировать H5 файлы")
    scan_onnx: bool = Field(True, description="Сканировать ONNX файлы")

class ScanResponse(BaseModel):
    scan_id: str = Field(..., description="ID сканирования")
    status: ScanStatus = Field(..., description="Статус сканирования")
    file_path: str = Field(..., description="Путь к отсканированному файлу")
    issues: List[SecurityIssue] = Field(default=[], description="Найденные проблемы")
    scan_summary: Dict[str, Any] = Field(..., description="Сводка сканирования")
    timestamp: str = Field(..., description="Время сканирования")
    hrefStatus: str = Field(None, description = "Ссылка на статус сканирования")

class ScanSummary(BaseModel):
    total_files: int = Field(..., description="Всего файлов")
    scanned_files: int = Field(..., description="Отсканировано файлов")
    issues_found: int = Field(..., description="Найдено проблем")
    safe_files: int = Field(..., description="Безопасных файлов")
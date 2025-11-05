from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
import os
import aiofiles
from typing import List, Optional
import logging
from logging.config import dictConfig

from app.models import ScanRequest, ScanResponse, ScanStatus
from app.scanner import scanner
from app.config import config_manager, settings

# Настройка логирования
def setup_logging():
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': settings.logging.format
            }
        },
        'handlers': {
            'default': {
                'level': settings.logging.level,
                'formatter': 'default',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'level': settings.logging.level,
                'formatter': 'default',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(settings.paths.logs_dir, 'modelscan_api.log'),
                'maxBytes': settings.logging.max_file_size,
                'backupCount': settings.logging.backup_count
            }
        },
        'loggers': {
            '': {
                'handlers': ['default', 'file'],
                'level': settings.logging.level,
                'propagate': False
            }
        }
    }
    
    dictConfig(logging_config)

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.api.title,
    version=settings.api.version,
    description=settings.api.description
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=settings.api.cors_allow_credentials,
    allow_methods=settings.api.cors_allow_methods,
    allow_headers=settings.api.cors_allow_headers,
)

# Зависимость для получения конфигурации
def get_settings():
    return config_manager.get_config()

@app.get("/")
async def root():
    """Корневой endpoint"""
    return {
        "message": settings.api.title,
        "version": settings.api.version,
        "endpoints": {
            "scan_file": "POST /scan/file",
            "scan_directory": "POST /scan/directory", 
            "scan_status": "GET /scan/{scan_id}/status",
            "scan_results": "GET /scan/{scan_id}/results",
            "config": "GET /config",
            "health": "GET /health"
        }
    }

@app.get("/config")
async def get_configuration(settings: Settings = Depends(get_settings)):
    """Возвращает текущую конфигурацию"""
    return JSONResponse(content=settings.dict())

@app.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Файл модели для сканирования"),
    settings: Settings = Depends(get_settings)
):
    """Сканирование одного файла модели"""
    logger.info(f"Начало сканирования файла: {file.filename}")
    
    # Проверяем расширение файла
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in settings.scanning.allowed_extensions:
        logger.warning(f"Попытка загрузки неподдерживаемого формата: {file_ext}")
        raise HTTPException(
            status_code=400,
            detail=f"Неподдерживаемый формат файла. Разрешенные форматы: {settings.scanning.allowed_extensions}"
        )
    
    # Генерируем ID сканирования
    scan_id = str(uuid.uuid4())
    
    # Сохраняем файл
    file_path = os.path.join(settings.paths.upload_dir, f"{scan_id}_{file.filename}")
    
    async with aiofiles.open(file_path, 'wb') as f:
        content = await file.read()
        
        # Проверяем размер файла
        if len(content) > settings.scanning.max_file_size:
            logger.warning(f"Файл слишком большой: {len(content)} байт")
            raise HTTPException(
                status_code=400,
                detail=f"Файл слишком большой. Максимальный размер: {settings.scanning.max_file_size} байт"
            )
        
        await f.write(content)
    
    logger.info(f"Файл сохранен: {file_path}, запуск сканирования")
    
    # Запускаем сканирование в фоне
    background_tasks.add_task(scanner.scan_file, file_path, scan_id)
    
    # Возвращаем начальный ответ
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        file_path=file_path,
        issues=[],
        scan_summary={},
        timestamp=str(datetime.now())
    )

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Получение статуса сканирования"""
    status = scanner.get_scan_status(scan_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    
    return status

@app.get("/scan/{scan_id}/results", response_model=ScanResponse)
async def get_scan_results(scan_id: str, settings: Settings = Depends(get_settings)):
    """Получение результатов сканирования"""
    result_file = os.path.join(settings.paths.scan_results_dir, f"{scan_id}.json")
    
    if not os.path.exists(result_file):
        raise HTTPException(status_code=404, detail="Результаты сканирования не найдены")
    
    # Читаем и возвращаем результаты
    async with aiofiles.open(result_file, 'r') as f:
        content = await f.read()
        
    return JSONResponse(content=content)

@app.get("/health")
async def health_check():
    """Проверка здоровья API"""
    return {
        "status": "healthy",
        "timestamp": str(datetime.now()),
        "active_scans": len(scanner.active_scans)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.api.host,
        port=settings.api.port,
        reload=settings.api.reload,
        workers=settings.api.workers
    )
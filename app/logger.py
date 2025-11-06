import logging
from config import settings
import os
from logging.config import dictConfig

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
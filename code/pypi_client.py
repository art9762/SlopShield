import requests
import logging
from datetime import datetime
from typing import Optional, Dict, Any

class PyPIClient:
    BASE_URL = "https://pypi.org/pypi/{name}/json"

    def __init__(self):
        self.session = requests.Session()

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Запрашивает метаданные пакета.
        Returns: JSON dict, если пакет есть. None, если 404 (Slopsquatting).
        """
        try:
            response = self.session.get(self.BASE_URL.format(name=name), timeout=5)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"Network error checking {name}: {e}")
            # В случае ошибки сети (не 404) считаем, что проверка не удалась, но не говорим, что пакета нет
            raise e

    def get_upload_time(self, data: Dict[str, Any]) -> Optional[datetime]:
        """
        Извлекает время загрузки последней версии.
        """
        try:
            # PyPI API возвращает список urls для текущей версии
            urls = data.get('urls', [])
            if not urls:
                # Если urls пуст, пробуем взять из releases
                version = data['info']['version']
                urls = data['releases'].get(version, [])
            
            if urls and 'upload_time_iso_8601' in urls[0]:
                # Формат: 2023-10-05T14:30:00.123456Z
                iso_date = urls[0]['upload_time_iso_8601']
                # python 3.11+ парсит Z корректно, для старых версий можно replace('Z', '+00:00')
                return datetime.fromisoformat(iso_date.replace('Z', '+00:00'))
            return None
        except (KeyError, IndexError, ValueError) as e:
            logging.warning(f"Could not parse upload time: {e}")
            return None
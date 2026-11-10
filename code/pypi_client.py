import requests
import logging
from datetime import datetime, timezone
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
            data = response.json()
            if (not isinstance(data, dict) or not isinstance(data.get("info"), dict)
                    or not isinstance(data["info"].get("version"), str)
                    or not data["info"]["version"]):
                raise ValueError("PyPI returned invalid package metadata")
            return data
        except requests.RequestException as e:
            logging.error(f"Network error checking {name}: {e}")
            # В случае ошибки сети (не 404) считаем, что проверка не удалась, но не говорим, что пакета нет
            raise e

    def get_upload_time(self, data: Dict[str, Any]) -> Optional[datetime]:
        """
        Извлекает время загрузки последней версии.
        """
        urls = data.get("urls") or []
        if not urls:
            releases = data.get("releases") or {}
            if isinstance(releases, dict):
                urls = releases.get(data.get("info", {}).get("version"), [])
        if not isinstance(urls, list):
            return None

        upload_times = []
        for file_info in urls:
            if not isinstance(file_info, dict):
                continue
            iso_date = file_info.get("upload_time_iso_8601")
            if not isinstance(iso_date, str):
                continue
            try:
                uploaded = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
            except ValueError:
                continue
            if uploaded.tzinfo is not None:
                upload_times.append(uploaded.astimezone(timezone.utc))
        # A release may have multiple wheels uploaded on different dates.
        # Its age starts at the first known file, not an arbitrary API ordering.
        return min(upload_times) if upload_times else None

import Levenshtein
from packaging.utils import canonicalize_name

class TyposquatDetector:
    # Hardcoded Top-List (сокращенный вариант для примера, в реальном проде список должен быть шире)
    POPULAR_PACKAGES = {
        'requests', 'flask', 'django', 'numpy', 'pandas', 'boto3', 'scikit-learn',
        'tensorflow', 'torch', 'fastapi', 'pydantic', 'sqlalchemy', 'beautifulsoup4',
        'urllib3', 'six', 'botocore', 'python-dateutil', 'setuptools', 'wheel', 'pip'
    }

    def check_typo(self, name: str) -> str | None:
        """
        Проверяет имя пакета на сходство с популярными библиотеками.
        Returns: Имя оригинального пакета, если обнаружен тайпосквоттинг, иначе None.
        """
        normalized_name = canonicalize_name(name)
        
        # Если пакет и так в белом списке - все ок
        if normalized_name in self.POPULAR_PACKAGES:
            return None

        for pop_pkg in sorted(self.POPULAR_PACKAGES, key=lambda pkg: (
            Levenshtein.distance(normalized_name, pkg), pkg
        )):
            dist = Levenshtein.distance(normalized_name, pop_pkg)
            
            # Дистанция <= 2 считается подозрительной (например, reqests -> requests, dist=1)
            # При этом проверяем, чтобы длина не была слишком маленькой (чтобы не флагать 'os' vs 'io')
            if 0 < dist <= 2 and len(normalized_name) > 3:
                return pop_pkg
        
        return None

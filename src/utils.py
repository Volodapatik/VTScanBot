# Вспомогательные функции
# Полная версия будет в следующем обновлении

def is_valid_hash(hash_str):
    """Проверяет валидность хеша"""
    return len(hash_str) in [32, 40, 64]

def is_valid_url(url):
    """Проверяет валидность URL"""
    return url.startswith(("http://", "https://"))

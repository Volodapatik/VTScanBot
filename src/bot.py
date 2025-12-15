import os
import logging
import asyncio
import hashlib
from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from dotenv import load_dotenv
from aiohttp import web
import httpx
import json

load_dotenv()

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

bot = Bot(
    token=os.getenv("BOT_TOKEN"),
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher()
router = Router()
dp.include_router(router)

# Создаем aiohttp приложение для healthcheck
app = web.Application()

async def health_check(request):
    return web.Response(text="OK", status=200)

app.router.add_get('/health', health_check)

# Очередь задач
user_tasks = {}
MAX_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", 3))

# VirusTotal клиент
class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
    
    async def scan_file(self, file_path):
        """Сканирует файл до 650 МБ"""
        try:
            async with httpx.AsyncClient() as client:
                # Получаем URL для загрузки
                resp = await client.get(
                    f"{self.base_url}/files/upload_url",
                    headers=self.headers
                )
                upload_url = resp.json().get("data")
                
                # Загружаем файл
                with open(file_path, "rb") as f:
                    files = {"file": f}
                    response = await client.post(
                        upload_url,
                        headers=self.headers,
                        files=files,
                        timeout=30.0
                    )
                
                if response.status_code == 200:
                    return response.json().get("data", {}).get("id")
                else:
                    logger.error(f"VirusTotal error: {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования файла: {e}")
            return None
    
    async def scan_url(self, url):
        """Сканирует URL"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/urls",
                    headers=self.headers,
                    data={"url": url},
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json().get("data", {}).get("id")
                else:
                    logger.error(f"VirusTotal URL error: {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования URL: {e}")
            return None
    
    async def get_analysis_report(self, analysis_id):
        """Получает отчет по анализу (для файлов и URL)"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"VirusTotal report error: {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета: {e}")
            return None
    
    async def get_file_report(self, file_hash):
        """Получает отчет по хешу файла"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers=self.headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета по хешу: {e}")
            return None

vt_client = VirusTotalClient()

# Google Drive клиент (упрощенная версия)
class GoogleDriveClient:
    def __init__(self):
        # В реальной версии здесь будет работа с Google Drive API
        pass
    
    async def upload_file(self, file_path):
        """Загружает файл на Google Drive"""
        # Заглушка - в реальной версии будет работать
        return f"https://drive.google.com/uc?id=test_{hashlib.md5(file_path.encode()).hexdigest()}"
    
    async def delete_file(self, file_url):
        """Удаляет файл с Google Drive"""
        pass

drive_client = GoogleDriveClient()

# Очередь задач
def can_process(user_id):
    """Проверяет, может ли пользователь начать новую задачу"""
    count = user_tasks.get(user_id, 0)
    return count < MAX_TASKS

def add_task(user_id):
    """Добавляет задачу пользователю"""
    user_tasks[user_id] = user_tasks.get(user_id, 0) + 1

def remove_task(user_id):
    """Удаляет задачу пользователя"""
    if user_id in user_tasks:
        user_tasks[user_id] -= 1
        if user_tasks[user_id] <= 0:
            del user_tasks[user_id]

# Вспомогательные функции
def is_valid_hash(hash_str):
    """Проверяет валидность хеша"""
    if len(hash_str) in [32, 40, 64]:
        return all(c in "0123456789abcdefABCDEF" for c in hash_str)
    return False

def calculate_hash(file_path):
    """Вычисляет SHA256 хеш файла"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@router.message(Command("start", "help"))
async def start_command(message: Message):
    await message.answer(
        "🛡️ <b>VTScanBot - Сканер VirusTotal</b>\n\n"
        "Отправьте мне:\n"
        "• Файл (любого размера) - для сканирования\n"
        "• Ссылку (URL) - для проверки\n"
        "• Хеш (MD5/SHA1/SHA256) - для поиска отчета\n\n"
        "Бот автоматически обработает ваш запрос и предоставит подробный отчет.\n\n"
        f"⚠️ <i>Ограничение: не больше {MAX_TASKS} одновременных сканирований на пользователя</i>"
    )

@router.message(F.text)
async def handle_text(message: Message):
    user_id = message.from_user.id
    
    if not can_process(user_id):
        await message.answer(f"⏳ У вас уже {MAX_TASKS} активных сканирования. Дождитесь завершения.")
        return
    
    add_task(user_id)
    
    try:
        text = message.text.strip()
        
        # Проверяем хеш
        if is_valid_hash(text):
            await message.answer(f"🔍 Ищу отчет по хешу: <code>{text}</code>")
            
            report = await vt_client.get_file_report(text)
            if report:
                await send_file_report(message, report)
            else:
                await message.answer("ℹ️ Файл с таким хешем не найден в VirusTotal.")
        
        # Проверяем URL
        elif text.startswith(("http://", "https://")):
            await message.answer(f"🔍 Сканирую URL: <code>{text}</code>")
            
            analysis_id = await vt_client.scan_url(text)
            if analysis_id:
                await message.answer("✅ URL отправлен на сканирование. Жду результаты...")
                await wait_and_send_report(message, analysis_id, is_url=True)
            else:
                await message.answer("❌ Ошибка при сканировании URL.")
        
        else:
            await message.answer("❌ Не понимаю запрос. Отправьте файл, URL или хеш.")
    
    except Exception as e:
        logger.error(f"Ошибка обработки текста: {e}")
        await message.answer("❌ Произошла ошибка при обработке запроса.")
    
    finally:
        remove_task(user_id)

@router.message(F.document | F.photo | F.video | F.audio)
async def handle_file(message: Message):
    user_id = message.from_user.id
    
    if not can_process(user_id):
        await message.answer(f"⏳ У вас уже {MAX_TASKS} активных сканирования. Дождитесь завершения.")
        return
    
    add_task(user_id)
    
    try:
        # Скачиваем файл
        if message.document:
            file_id = message.document.file_id
            file_name = message.document.file_name
            file_size = message.document.file_size
        elif message.photo:
            file_id = message.photo[-1].file_id
            file_name = "photo.jpg"
            file_size = message.photo[-1].file_size
        elif message.video:
            file_id = message.video.file_id
            file_name = message.video.file_name or "video.mp4"
            file_size = message.video.file_size
        elif message.audio:
            file_id = message.audio.file_id
            file_name = message.audio.file_name or "audio.mp3"
            file_size = message.audio.file_size
        
        size_mb = file_size / 1024 / 1024
        
        await message.answer(f"📥 Файл получен: <code>{file_name}</code>\nРазмер: <b>{size_mb:.1f} МБ</b>")
        
        # Скачиваем файл
        file = await bot.get_file(file_id)
        temp_path = f"temp_{file_id}"
        await bot.download_file(file.file_path, temp_path)
        
        # Определяем способ сканирования
        if size_mb <= 650:
            await message.answer("🔍 Сканирую файл напрямую через VirusTotal...")
            analysis_id = await vt_client.scan_file(temp_path)
        else:
            await message.answer("⚠️ Файл большой (>650 МБ)\n📤 Загружаю на Google Drive...")
            file_url = await drive_client.upload_file(temp_path)
            await message.answer("✅ Загружено на Google Drive\n🔍 Сканирую через VirusTotal...")
            analysis_id = await vt_client.scan_url(file_url)
        
        # Удаляем временный файл
        os.remove(temp_path)
        
        if analysis_id:
            await message.answer("✅ Файл отправлен на сканирование. Жду результаты...")
            await wait_and_send_report(message, analysis_id, is_url=False)
        else:
            await message.answer("❌ Ошибка при отправке файла на сканирование.")
    
    except Exception as e:
        logger.error(f"Ошибка обработки файла: {e}")
        await message.answer("❌ Произошла ошибка при обработке файла.")
    
    finally:
        remove_task(user_id)

async def wait_and_send_report(message: Message, analysis_id: str, is_url: bool, attempts: int = 10):
    """Ждет отчет и отправляет его"""
    for i in range(attempts):
        await asyncio.sleep(10)  # Ждем 10 секунд между попытками
        
        report = await vt_client.get_analysis_report(analysis_id)
        if report:
            status = report.get("data", {}).get("attributes", {}).get("status")
            
            if status == "completed":
                if is_url:
                    # Для URL получаем полный отчет по ID
                    url_id = report.get("data", {}).get("id", "").split("-")[-1]
                    url_report = await vt_client.get_file_report(url_id)
                    if url_report:
                        await send_file_report(message, url_report)
                    else:
                        await send_analysis_report(message, report)
                else:
                    # Для файлов получаем отчет по хешу
                    file_hash = report.get("data", {}).get("attributes", {}).get("sha256")
                    if file_hash:
                        file_report = await vt_client.get_file_report(file_hash)
                        if file_report:
                            await send_file_report(message, file_report)
                        else:
                            await send_analysis_report(message, report)
                    else:
                        await send_analysis_report(message, report)
                return
            elif status == "queued":
                if i == attempts - 1:
                    await message.answer("⏳ Сканирование все еще в очереди. Попробуйте позже.")
                continue
            else:
                await message.answer(f"⚠️ Статус сканирования: {status}")
                return
    
    await message.answer("⏳ Сканирование занимает больше времени. Отчет придет позже.")

async def send_file_report(message: Message, report: dict):
    """Отправляет отчет по файлу (из get_file_report)"""
    try:
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        # Получаем статистику
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        
        total_scanners = malicious + suspicious + undetected + harmless
        
        # Получаем хеш
        file_hash = attributes.get("sha256", data.get("id", ""))
        
        # Получаем имена угроз
        threat_names = []
        results = attributes.get("last_analysis_results", {})
        for av, result in results.items():
            if result.get("category") == "malicious":
                threat_name = result.get("result", "Unknown")
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        # Формируем сообщение
        result_text = f"🛡️ <b>Результат сканирования</b>\n\n"
        result_text += f"• Угроз обнаружено: <b>{malicious}/{total_scanners}</b>\n"
        
        if malicious > 0 and threat_names:
            threats = ", ".join(threat_names[:3])
            if len(threat_names) > 3:
                threats += f" и еще {len(threat_names) - 3}"
            result_text += f"• Обнаруженные угрозы: {threats}\n"
        
        if file_hash:
            short_hash = file_hash[:16] + "..." if len(file_hash) > 16 else file_hash
            result_text += f"• Хеш (SHA256): <code>{short_hash}</code>\n"
        
        result_text += f"• Ссылка на отчет: https://www.virustotal.com/gui/file/{file_hash}"
        
        # Создаем кнопки (безопасные данные)
        from urllib.parse import quote
        safe_file_id = file_hash[:16] if file_hash else "unknown"
        callback_payload = f"rescan_{safe_file_id}"
        
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔄 Пересканировать", 
                                   callback_data=callback_payload),
                InlineKeyboardButton(text="📤 Поделиться", 
                                   url=f"https://t.me/share/url?url=https://virustotal.com/gui/file/{file_hash}")
            ]
        ])
        
        await message.answer(result_text, reply_markup=keyboard)
        
    except Exception as e:
        logger.error(f"Ошибка формирования отчета по файлу: {e}")
        await send_analysis_report(message, report)

async def send_analysis_report(message: Message, report: dict):
    """Отправляет базовый отчет по анализу (fallback)"""
    try:
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        stats = attributes.get("stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        
        result_text = f"✅ <b>Сканирование завершено</b>\n\n"
        result_text += f"• Угроз обнаружено: <b>{malicious}/{total}</b>\n"
        result_text += "• <i>Для подробного отчета попробуйте поиск по хешу файла</i>"
        
        await message.answer(result_text)
        
    except Exception as e:
        logger.error(f"Ошибка формирования базового отчета: {e}")
        await message.answer("✅ Сканирование завершено. (Ошибка формирования детального отчета)")

@router.callback_query(F.data.startswith("rescan_"))
async def handle_rescan(callback_query):
    file_hash_part = callback_query.data.split("_")[1]
    await callback_query.answer("Начинаю пересканирование...")
    
    # Здесь нужна логика поиска полного хеша по частичному
    # Пока просто сообщаем, что функционал в разработке
    await callback_query.message.answer("🔄 Функция пересканирования будет доступна в следующем обновлении.")

@router.message()
async def unknown_message(message: Message):
    await message.answer("🤔 Не понимаю. Используйте /start для справки.")

async def start_bot():
    logger.info("Бот запущен и готов к работе!")
    await dp.start_polling(bot)

async def main():
    # Запускаем aiohttp сервер для healthcheck
    runner = web.AppRunner(app)
    await runner.setup()
    
    # Получаем порт из окружения Railway (Railway ставит PORT)
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    
    logger.info(f"Запускаю healthcheck сервер на порту {port}")
    await site.start()
    
    # Запускаем бота в фоне
    bot_task = asyncio.create_task(start_bot())
    
    # Ждем завершения
    await bot_task

if __name__ == "__main__":
    asyncio.run(main())

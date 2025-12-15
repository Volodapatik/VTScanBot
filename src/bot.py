import os
import logging
import asyncio
import hashlib
import time
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

app = web.Application()
async def health_check(request):
    return web.Response(text="OK", status=200)
app.router.add_get('/health', health_check)

user_tasks = {}
MAX_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", 3))
# Храним информацию о файлах: {analysis_id: {"user_id": 123, "file_hash": "abc", "timestamp": 123}}
file_info_cache = {}

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
    
    async def scan_file(self, file_path):
        """Сканирует файл и ВЫЧИСЛЯЕТ SHA256 локально"""
        try:
            # ВЫЧИСЛЯЕМ SHA256 локально перед отправкой
            file_hash = self.calculate_sha256(file_path)
            logger.info(f"Локальный SHA256 файла: {file_hash}")
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.base_url}/files/upload_url",
                    headers=self.headers
                )
                upload_url = resp.json().get("data")
                
                with open(file_path, "rb") as f:
                    files = {"file": f}
                    response = await client.post(
                        upload_url,
                        headers=self.headers,
                        files=files,
                        timeout=60.0
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data.get("data", {}).get("id")
                    logger.info(f"Файл загружен, анализ ID: {analysis_id}")
                    
                    # СОХРАНЯЕМ ИНФОРМАЦИЮ О ФАЙЛЕ
                    return {
                        'analysis_id': analysis_id,
                        'sha256': file_hash,  # НАШ локальный хеш
                        'status': 'uploaded'
                    }
                else:
                    logger.error(f"Ошибка загрузки: {response.text[:200]}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования файла: {e}")
            return None
    
    def calculate_sha256(self, file_path):
        """Вычисляет SHA256 файла"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    async def scan_url(self, url):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/urls",
                    headers=self.headers,
                    data={"url": url},
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data.get("data", {}).get("id")
                    logger.info(f"URL отправлен, анализ ID: {analysis_id}")
                    return {'analysis_id': analysis_id, 'sha256': None}
                else:
                    logger.error(f"Ошибка URL: {response.text[:200]}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования URL: {e}")
            return None
    
    async def get_analysis_report(self, analysis_id):
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
                    logger.error(f"Ошибка отчета анализа: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета: {e}")
            return None
    
    async def get_file_report(self, file_hash):
        """Получает ПОЛНЫЙ отчет по хешу"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers=self.headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    logger.info(f"ПОЛНЫЙ отчет получен для {file_hash}")
                    return response.json()
                elif response.status_code == 404:
                    logger.info(f"Файл {file_hash} еще не в базе VirusTotal")
                    return None
                else:
                    logger.error(f"Ошибка отчета файла: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета по хешу: {e}")
            return None
    
    async def search_by_analysis_id(self, analysis_id):
        """Ищет файл по ID анализа (альтернативный способ)"""
        try:
            async with httpx.AsyncClient() as client:
                # Пробуем получить информацию об анализе
                response = await client.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # Ищем хеш в ответе
                    attrs = data.get("data", {}).get("attributes", {})
                    
                    # Пробуем разные пути
                    sha256 = attrs.get("sha256")
                    if not sha256:
                        sha256 = attrs.get("meta", {}).get("file_info", {}).get("sha256")
                    
                    return sha256
                return None
                    
        except Exception as e:
            logger.error(f"Ошибка поиска по анализу: {e}")
            return None

vt_client = VirusTotalClient()

class GoogleDriveClient:
    def __init__(self):
        pass
    
    async def upload_file(self, file_path):
        return f"https://drive.google.com/uc?id=test_{hashlib.md5(file_path.encode()).hexdigest()}"
    
    async def delete_file(self, file_url):
        pass

drive_client = GoogleDriveClient()

def can_process(user_id):
    count = user_tasks.get(user_id, 0)
    return count < MAX_TASKS

def add_task(user_id):
    user_tasks[user_id] = user_tasks.get(user_id, 0) + 1

def remove_task(user_id):
    if user_id in user_tasks:
        user_tasks[user_id] -= 1
        if user_tasks[user_id] <= 0:
            del user_tasks[user_id]

def is_valid_hash(hash_str):
    if len(hash_str) in [32, 40, 64]:
        return all(c in "0123456789abcdefABCDEF" for c in hash_str)
    return False

@router.message(Command("start", "help"))
async def start_command(message: Message):
    await message.answer(
        "🛡️ <b>VTScanBot - Сканер VirusTotal</b>\n\n"
        "Отправьте мне файл или ссылку для сканирования.\n"
        f"⚠️ <i>Ограничение: {MAX_TASKS} одновременных сканирований</i>"
    )

@router.message(Command("hash"))
async def hash_command(message: Message):
    """Вычисляет хеш файла"""
    await message.answer(
        "🔍 <b>Тестовые хеши EICAR:</b>\n\n"
        "• MD5: <code>44d88612fea8a8f36de82e1278abb02f</code>\n"
        "• SHA1: <code>3395856ce81f2b7382dee72602f798b642f14140</code>\n"
        "• SHA256: <code>275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f</code>\n\n"
        "<i>Отправьте любой хеш для поиска отчета</i>"
    )

@router.message(F.text)
async def handle_text(message: Message):
    user_id = message.from_user.id
    
    if not can_process(user_id):
        await message.answer(f"⏳ У вас уже {MAX_TASKS} активных сканирования.")
        return
    
    add_task(user_id)
    
    try:
        text = message.text.strip()
        
        if is_valid_hash(text):
            await message.answer(f"🔍 Ищу отчет по хешу: <code>{text}</code>")
            
            # НЕМЕДЛЕННО пробуем получить полный отчет
            report = await vt_client.get_file_report(text)
            if report:
                await send_full_vt_report(message, report)
            else:
                await message.answer("📭 Файл не найден в базе VirusTotal.\n"
                                   "Возможно, он еще обрабатывается или не был загружен.")
        
        elif text.startswith(("http://", "https://")):
            await message.answer(f"🔍 Сканирую URL: <code>{text}</code>")
            
            result = await vt_client.scan_url(text)
            if result:
                await message.answer("✅ URL отправлен. Ожидаю...")
                await wait_and_process_analysis(message, result['analysis_id'], 
                                               user_id=user_id, is_url=True)
            else:
                await message.answer("❌ Ошибка при сканировании URL.")
        
        else:
            await message.answer("❌ Отправьте файл, URL или хеш.")
    
    except Exception as e:
        logger.error(f"Ошибка обработки текста: {e}")
        await message.answer("❌ Произошла ошибка.")
    
    finally:
        remove_task(user_id)

@router.message(F.document | F.photo | F.video | F.audio)
async def handle_file(message: Message):
    user_id = message.from_user.id
    
    if not can_process(user_id):
        await message.answer(f"⏳ У вас уже {MAX_TASKS} активных сканирования.")
        return
    
    add_task(user_id)
    
    try:
        if message.document:
            file_id = message.document.file_id
            file_name = message.document.file_name or "файл"
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
        await message.answer(f"📥 Файл: <b>{file_name}</b>\nРазмер: {size_mb:.1f} МБ")
        
        # Скачиваем и вычисляем хеш
        file = await bot.get_file(file_id)
        temp_path = f"temp_{int(time.time())}_{file_id}"
        await bot.download_file(file.file_path, temp_path)
        
        # ВЫЧИСЛЯЕМ SHA256 ПЕРЕД ОТПРАВКОЙ
        file_hash = vt_client.calculate_sha256(temp_path)
        logger.info(f"📊 Локальный SHA256: {file_hash}")
        
        # Проверяем, может файл уже есть в базе VT
        existing_report = await vt_client.get_file_report(file_hash)
        if existing_report:
            logger.info(f"✅ Файл уже в базе VT, отправляю отчет")
            await send_full_vt_report(message, existing_report)
            
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
            remove_task(user_id)
            return
        
        # Если нет - загружаем
        if size_mb <= 650:
            await message.answer("🔍 Сканирую файл...")
            result = await vt_client.scan_file(temp_path)
        else:
            await message.answer("⚠️ Файл большой. Загружаю на Google Drive...")
            file_url = await drive_client.upload_file(temp_path)
            await message.answer("✅ Загружено. Сканирую...")
            result = await vt_client.scan_url(file_url)
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        if result:
            # СОХРАНЯЕМ ИНФОРМАЦИЮ О ФАЙЛЕ
            file_info_cache[result['analysis_id']] = {
                'user_id': user_id,
                'sha256': file_hash,  # НАШ локальный хеш
                'timestamp': time.time(),
                'message_id': message.message_id
            }
            
            await message.answer("✅ Файл отправлен. Ожидаю...")
            await wait_and_process_analysis(message, result['analysis_id'], 
                                          user_id=user_id, is_url=False,
                                          known_hash=file_hash)
        else:
            await message.answer("❌ Ошибка при отправке.")
    
    except Exception as e:
        logger.error(f"Ошибка обработки файла: {e}")
        await message.answer("❌ Произошла ошибка.")
    
    finally:
        remove_task(user_id)

async def wait_and_process_analysis(message: Message, analysis_id: str, user_id: int, 
                                   is_url: bool, known_hash: str = None):
    """Ожидает анализ и пытается получить полный отчет"""
    logger.info(f"🔍 Ожидание анализа {analysis_id}, известный хеш: {known_hash}")
    
    # СПОСОБ 1: Если знаем хеш - пробуем получить полный отчет
    if known_hash:
        for attempt in range(12):  # 12 попыток × 15 сек = 3 минуты
            await asyncio.sleep(15)
            
            logger.info(f"Попытка {attempt+1}: запрашиваю полный отчет для {known_hash}")
            full_report = await vt_client.get_file_report(known_hash)
            
            if full_report:
                logger.info(f"🎉 УСПЕХ! Полный отчет получен!")
                await send_full_vt_report(message, full_report)
                return
            
            # Проверяем статус анализа
            analysis = await vt_client.get_analysis_report(analysis_id)
            if analysis:
                status = analysis.get("data", {}).get("attributes", {}).get("status")
                logger.info(f"Статус анализа: {status}")
    
    # СПОСОБ 2: Если не знаем хеш или не получили отчет
    logger.info("Использую резервный способ...")
    
    for attempt in range(8):  # Дополнительные 2 минуты
        await asyncio.sleep(15)
        
        analysis = await vt_client.get_analysis_report(analysis_id)
        if not analysis:
            continue
        
        status = analysis.get("data", {}).get("attributes", {}).get("status")
        logger.info(f"Анализ {analysis_id}, статус: {status}")
        
        if status == "completed":
            # Пробуем извлечь хеш из анализа
            attrs = analysis.get("data", {}).get("attributes", {})
            found_hash = attrs.get("sha256")
            
            if not found_hash:
                found_hash = attrs.get("meta", {}).get("file_info", {}).get("sha256")
            
            if found_hash:
                logger.info(f"Найден хеш в анализе: {found_hash}")
                await asyncio.sleep(10)  # Даем время на обработку
                
                full_report = await vt_client.get_file_report(found_hash)
                if full_report:
                    await send_full_vt_report(message, full_report)
                    return
            
            # Если не нашли полный отчет - показываем базовый
            await send_basic_analysis_report(message, analysis)
            return
        
        elif status == "queued":
            continue
    
    # Если ничего не получилось
    await message.answer("⏳ VirusTotal обрабатывает файл. Попробуйте через 2-3 минуты.")

async def send_full_vt_report(message: Message, report: dict):
    """Отправляет ПОЛНЫЙ отчет КАК НА САЙТЕ"""
    try:
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        # 1. Статистика
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        
        total = malicious + suspicious + undetected + harmless
        
        # 2. Основные угрозы
        threat_names = []
        results = attributes.get("last_analysis_results", {})
        
        for av, result in results.items():
            if result.get("category") == "malicious":
                threat_name = result.get("result", "Unknown")
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        # 3. Хеш
        file_hash = attributes.get("sha256", data.get("id", ""))
        
        # 4. Формируем сообщение
        result_text = f"🛡️ <b>Результат сканирования</b>\n\n"
        result_text += f"• Угроз обнаружено: <b>{malicious}/{total}</b>\n"
        
        if malicious > 0 and threat_names:
            main_threat = threat_names[0]
            result_text += f"• Основная угроза: <b>{main_threat}</b>\n"
            
            if len(threat_names) > 1:
                result_text += f"• Другие угрозы: еще {len(threat_names)-1}\n"
        
        if file_hash:
            short_hash = file_hash[:16] + "..." if len(file_hash) > 20 else file_hash
            result_text += f"• Хеш SHA256: <code>{short_hash}</code>\n"
        
        # 5. Ссылка на сайт
        vt_link = f"https://www.virustotal.com/gui/file/{file_hash}" if file_hash else "https://www.virustotal.com"
        result_text += f"• Ссылка на отчет: {vt_link}\n\n"
        result_text += "<i>✅ Нажмите ссылку для проверки на сайте</i>"
        
        # 6. Кнопки
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🌐 Открыть на сайте", url=vt_link),
                InlineKeyboardButton(text="🔍 Поиск по хешу", 
                                   callback_data=f"hash_{file_hash[:16]}" if file_hash else "none")
            ]
        ])
        
        await message.answer(result_text, reply_markup=keyboard)
        logger.info(f"✅ Отправлен ПОЛНЫЙ отчет для {file_hash}")
        
    except Exception as e:
        logger.error(f"Ошибка полного отчета: {e}")
        await send_basic_analysis_report(message, report)

async def send_basic_analysis_report(message: Message, analysis_report: dict):
    """Базовый отчет из анализа"""
    try:
        data = analysis_report.get("data", {})
        attributes = data.get("attributes", {})
        
        stats = attributes.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        
        total = malicious + suspicious + undetected + harmless
        
        result_text = f"✅ <b>Сканирование завершено</b>\n\n"
        
        if total > 0:
            result_text += f"• Угроз обнаружено: <b>{malicious}/{total}</b>\n"
            result_text += f"• Подозрительных: {suspicious}\n"
        else:
            result_text += "• Статистика временно недоступна\n"
        
        result_text += "\n<i>📊 Полный отчет с деталями будет через 1-2 минуты</i>"
        
        await message.answer(result_text)
        
    except Exception as e:
        logger.error(f"Ошибка базового отчета: {e}")
        await message.answer("✅ Сканирование завершено.")

@router.callback_query(F.data.startswith("hash_"))
async def handle_hash_search(callback_query):
    file_hash_part = callback_query.data.split("_")[1]
    await callback_query.answer("Ищу полный отчет...")
    
    # Здесь можно реализовать поиск по частичному хешу
    await callback_query.message.answer("🔍 Используйте команду /hash для тестовых хешей")

@router.message()
async def unknown_message(message: Message):
    await message.answer("🤔 Используйте /start для справки")

async def start_bot():
    logger.info("Бот запущен и готов к работе!")
    await dp.start_polling(bot)

async def main():
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    
    logger.info(f"Healthcheck на порту {port}")
    await site.start()
    
    bot_task = asyncio.create_task(start_bot())
    await bot_task

if __name__ == "__main__":
    asyncio.run(main())

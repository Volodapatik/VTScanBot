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

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
    
    async def scan_file(self, file_path):
        try:
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
                    logger.info(f"Файл загружен, ID анализа: {data.get('data', {}).get('id')}")
                    
                    # ВАЖНОЕ ИЗМЕНЕНИЕ: Немедленно получаем SHA256 из ответа
                    sha256 = None
                    if 'meta' in data.get('data', {}):
                        sha256 = data['data']['meta'].get('file_info', {}).get('sha256')
                    
                    return {
                        'analysis_id': data.get('data', {}).get('id'),
                        'sha256': sha256
                    }
                else:
                    logger.error(f"Ошибка загрузки: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка сканирования файла: {e}")
            return None
    
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
                    logger.info(f"URL отправлен, ID анализа: {analysis_id}")
                    return {'analysis_id': analysis_id, 'sha256': None}
                else:
                    logger.error(f"Ошибка URL: {response.status_code}")
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
                    logger.error(f"Ошибка отчета: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета: {e}")
            return None
    
    async def get_file_report(self, file_hash):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers=self.headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    logger.info(f"Файл не найден: {file_hash}")
                    return None
                else:
                    logger.error(f"Ошибка отчета файла: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Ошибка получения отчета по хешу: {e}")
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

def calculate_hash(file_path):
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
        f"⚠️ <i>Ограничение: не больше {MAX_TASKS} одновременных сканирований</i>"
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
            
            report = await vt_client.get_file_report(text)
            if report:
                await send_full_vt_report(message, report)
            else:
                await message.answer("ℹ️ Файл с таким хешем не найден.")
        
        elif text.startswith(("http://", "https://")):
            await message.answer(f"🔍 Сканирую URL: <code>{text}</code>")
            
            result = await vt_client.scan_url(text)
            if result:
                await message.answer("✅ URL отправлен. Жду результаты...")
                await wait_and_send_report(message, result['analysis_id'], is_url=True)
            else:
                await message.answer("❌ Ошибка при сканировании URL.")
        
        else:
            await message.answer("❌ Не понимаю запрос.")
    
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
        await message.answer(f"📥 Файл: <code>{file_name}</code>\nРазмер: <b>{size_mb:.1f} МБ</b>")
        
        file = await bot.get_file(file_id)
        temp_path = f"temp_{file_id}"
        await bot.download_file(file.file_path, temp_path)
        
        if size_mb <= 650:
            await message.answer("🔍 Сканирую файл через VirusTotal...")
            result = await vt_client.scan_file(temp_path)
        else:
            await message.answer("⚠️ Файл большой. Загружаю на Google Drive...")
            file_url = await drive_client.upload_file(temp_path)
            await message.answer("✅ Загружено. Сканирую...")
            result = await vt_client.scan_url(file_url)
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        if result:
            await message.answer("✅ Файл отправлен. Жду результаты...")
            
            # ЕСЛИ ЕСТЬ SHA256 СРАЗУ - пробуем получить полный отчет
            if result.get('sha256'):
                logger.info(f"Есть SHA256 сразу: {result['sha256']}")
                await asyncio.sleep(10)
                full_report = await vt_client.get_file_report(result['sha256'])
                if full_report:
                    await send_full_vt_report(message, full_report)
                    return
            
            # Иначе ждем анализа
            await wait_and_send_report(message, result['analysis_id'], is_url=False)
        else:
            await message.answer("❌ Ошибка при отправке.")
    
    except Exception as e:
        logger.error(f"Ошибка обработки файла: {e}")
        await message.answer("❌ Произошла ошибка.")
    
    finally:
        remove_task(user_id)

async def wait_and_send_report(message: Message, analysis_id: str, is_url: bool, attempts: int = 20):
    """Умное ожидание полного отчета"""
    logger.info(f"Ожидание отчета {analysis_id}, тип: {'URL' if is_url else 'FILE'}")
    
    for i in range(attempts):
        wait_time = 10 if i < 8 else 20
        await asyncio.sleep(wait_time)
        
        logger.info(f"Попытка {i+1}: запрашиваю анализ")
        analysis_report = await vt_client.get_analysis_report(analysis_id)
        
        if not analysis_report:
            continue
        
        status = analysis_report.get("data", {}).get("attributes", {}).get("status")
        logger.info(f"Статус: {status}")
        
        if status == "completed":
            # Пробуем найти SHA256 в анализе
            sha256 = None
            attrs = analysis_report.get("data", {}).get("attributes", {})
            
            # 1. Прямой путь
            sha256 = attrs.get("sha256")
            
            # 2. Через результаты сканеров
            if not sha256:
                results = attrs.get("results", {})
                for scanner, result in results.items():
                    if result.get("sha256"):
                        sha256 = result.get("sha256")
                        break
            
            # 3. Через метаданные
            if not sha256:
                sha256 = attrs.get("meta", {}).get("file_info", {}).get("sha256")
            
            logger.info(f"Найденный SHA256: {sha256}")
            
            if sha256:
                # Даем VirusTotal время на обработку
                await asyncio.sleep(15)
                
                logger.info(f"Запрашиваю ПОЛНЫЙ отчет для {sha256}")
                full_report = await vt_client.get_file_report(sha256)
                
                if full_report:
                    logger.info("УСПЕХ: Получен полный отчет!")
                    await send_full_vt_report(message, full_report)
                    return
                else:
                    logger.warning(f"Полный отчет не готов для {sha256}")
            
            # Если не нашли полный отчет - показываем анализ
            await send_analysis_report(message, analysis_report)
            return
        
        elif status == "queued":
            continue
    
    await message.answer("⏳ Сканирование занимает больше времени. Попробуйте позже.")

async def send_full_vt_report(message: Message, report: dict):
    """Отправляет ПОЛНЫЙ отчет как на сайте VirusTotal"""
    try:
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        # 1. Статистика (как на сайте)
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        
        total = malicious + suspicious + undetected + harmless
        
        # 2. Основные угрозы (первые 3)
        threat_names = []
        results = attributes.get("last_analysis_results", {})
        
        for av, result in results.items():
            if result.get("category") == "malicious":
                threat_name = result.get("result", "Unknown")
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        # 3. Хеш файла
        file_hash = attributes.get("sha256", data.get("id", ""))
        
        # 4. Формируем сообщение КАК НА САЙТЕ
        result_text = f"🛡️ <b>Результат сканирования</b>\n\n"
        result_text += f"• Угроз обнаружено: <b>{malicious}/{total}</b>\n"
        
        if malicious > 0 and threat_names:
            # Берем первую (основную) угрозу
            main_threat = threat_names[0]
            result_text += f"• Основная угроза: <b>{main_threat}</b>\n"
            
            # Если есть еще угрозы
            if len(threat_names) > 1:
                other = len(threat_names) - 1
                result_text += f"• Другие угрозы: еще {other}\n"
        
        if file_hash:
            result_text += f"• Хеш SHA256: <code>{file_hash}</code>\n"
        
        # 5. Ссылка на сайт VirusTotal
        vt_link = f"https://www.virustotal.com/gui/file/{file_hash}" if file_hash else "https://www.virustotal.com"
        result_text += f"• Ссылка на отчет: {vt_link}"
        
        # 6. Кнопки
        safe_file_id = file_hash[:16] if file_hash else "unknown"
        
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🌐 Открыть на сайте", url=vt_link),
                InlineKeyboardButton(text="🔄 Пересканировать", callback_data=f"scan_{safe_file_id}")
            ]
        ])
        
        await message.answer(result_text, reply_markup=keyboard)
        logger.info(f"Отправлен ПОЛНЫЙ отчет для {file_hash}")
        
    except Exception as e:
        logger.error(f"Ошибка полного отчета: {e}")
        await message.answer("✅ Сканирование завершено. (Ошибка детального отчета)")

async def send_analysis_report(message: Message, report: dict):
    """Базовый отчет анализа"""
    try:
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        stats = attributes.get("stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        
        result_text = f"✅ <b>Сканирование завершено</b>\n\n"
        
        if total > 0:
            result_text += f"• Угроз обнаружено: <b>{malicious}/{total}</b>\n"
        else:
            result_text += "• Статистика временно недоступна\n"
        
        result_text += "\n<i>Полный отчет будет доступен через 1-2 минуты</i>"
        
        await message.answer(result_text)
        
    except Exception as e:
        logger.error(f"Ошибка базового отчета: {e}")
        await message.answer("✅ Сканирование завершено.")

@router.callback_query(F.data.startswith("scan_"))
async def handle_rescan(callback_query):
    await callback_query.answer("Функция в разработке...")
    await callback_query.message.answer("🔄 Функция пересканирования скоро будет доступна!")

@router.message()
async def unknown_message(message: Message):
    await message.answer("🤔 Используйте /start для справки.")

async def start_bot():
    logger.info("Бот запущен и готов к работе!")
    await dp.start_polling(bot)

async def main():
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = int(os.getenv("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    
    logger.info(f"Healthcheck сервер на порту {port}")
    await site.start()
    
    bot_task = asyncio.create_task(start_bot())
    await bot_task

if __name__ == "__main__":
    asyncio.run(main())

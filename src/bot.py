import os
import logging
import asyncio
from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from dotenv import load_dotenv

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

# Счетчик задач для пользователей
user_tasks = {}

@router.message(Command("start", "help"))
async def start_command(message: Message):
    await message.answer(
        "🛡️ <b>VTScanBot - Сканер VirusTotal</b>\n\n"
        "Отправьте мне:\n"
        "• Файл (любого размера) - для сканирования\n"
        "• Ссылку (URL) - для проверки\n"
        "• Хеш (MD5/SHA1/SHA256) - для поиска отчета\n\n"
        "Бот автоматически обработает ваш запрос и предоставит подробный отчет.\n\n"
        "⚠️ <i>Ограничение: не больше 3 одновременных сканирований на пользователя</i>"
    )

@router.message(F.text)
async def handle_text(message: Message):
    user_id = message.from_user.id
    
    # Проверяем лимит задач
    if user_id in user_tasks and user_tasks[user_id] >= 3:
        await message.answer("⏳ У вас уже 3 активных сканирования. Дождитесь завершения.")
        return
    
    # Увеличиваем счетчик задач
    user_tasks[user_id] = user_tasks.get(user_id, 0) + 1
    
    try:
        text = message.text.strip()
        
        # Проверяем, является ли текст хешем
        if len(text) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in text):
            await message.answer(f"🔍 Хеш получен: {text}\n\nИщу отчет в VirusTotal...")
            await asyncio.sleep(2)  # Имитация работы
            await message.answer("✅ Функционал хешей будет реализован в следующем обновлении")
        
        # Проверяем, является ли текст URL
        elif text.startswith(("http://", "https://")):
            await message.answer(f"🔍 URL получен: {text}\n\nСканирую...")
            await asyncio.sleep(2)  # Имитация работы
            await message.answer("✅ Функционал URL будет реализован в следующем обновлении")
        
        else:
            await message.answer("❌ Не понимаю запрос. Отправьте файл, URL или хеш.")
    
    finally:
        # Уменьшаем счетчик задач
        if user_id in user_tasks:
            user_tasks[user_id] -= 1
            if user_tasks[user_id] <= 0:
                del user_tasks[user_id]

@router.message(F.document | F.photo | F.video | F.audio)
async def handle_file(message: Message):
    user_id = message.from_user.id
    
    # Проверяем лимит задач
    if user_id in user_tasks and user_tasks[user_id] >= 3:
        await message.answer("⏳ У вас уже 3 активных сканирования. Дождитесь завершения.")
        return
    
    # Увеличиваем счетчик задач
    user_tasks[user_id] = user_tasks.get(user_id, 0) + 1
    
    try:
        # Определяем информацию о файле
        if message.document:
            file_name = message.document.file_name
            file_size = message.document.file_size
        elif message.photo:
            file_name = "photo.jpg"
            file_size = message.photo[-1].file_size
        elif message.video:
            file_name = message.video.file_name or "video.mp4"
            file_size = message.video.file_size
        elif message.audio:
            file_name = message.audio.file_name or "audio.mp3"
            file_size = message.audio.file_size
        
        size_mb = file_size / 1024 / 1024
        
        await message.answer(f"📥 Файл получен: <code>{file_name}</code>\nРазмер: <b>{size_mb:.1f} МБ</b>")
        
        # Имитация сканирования
        await asyncio.sleep(1)
        
        if size_mb <= 650:
            await message.answer("🔍 Сканирую файл напрямую через VirusTotal API...")
            await asyncio.sleep(3)
        else:
            await message.answer("⚠️ Файл большой (>650 МБ)\n📤 Загружаю на Google Drive...")
            await asyncio.sleep(3)
            await message.answer("✅ Загружено на Google Drive\n🔍 Сканирую через VirusTotal...")
            await asyncio.sleep(2)
        
        # Имитация готового отчета
        await message.answer("✅ Сканирование завершено!")
        
        # Пример отчета
        report_text = (
            "🛡️ <b>Результат сканирования</b>\n\n"
            "• Угроз обнаружено: <b>2/73</b>\n"
            "• Тип угрозы: Trojan.Win32.Generic\n"
            "• Ссылка на отчет: https://www.virustotal.com/gui/file/example123\n\n"
            "<i>Это тестовый отчет. Полный функционал будет в следующем обновлении.</i>"
        )
        
        # Кнопки
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text="🔄 Пересканировать", callback_data="rescan"),
                InlineKeyboardButton(text="📤 Поделиться", 
                                   url="https://t.me/share/url?url=https://virustotal.com")
            ]
        ])
        
        await message.answer(report_text, reply_markup=keyboard)
        
        # Имитация удаления файла через 15 минут (для больших файлов)
        if size_mb > 650:
            await message.answer("🗑️ <i>Файл будет автоматически удален с Google Drive через 15 минут</i>")
    
    except Exception as e:
        logger.error(f"Ошибка обработки файла: {e}")
        await message.answer("❌ Произошла ошибка при обработке файла.")
    
    finally:
        # Уменьшаем счетчик задач
        if user_id in user_tasks:
            user_tasks[user_id] -= 1
            if user_tasks[user_id] <= 0:
                del user_tasks[user_id]

@router.message()
async def unknown_message(message: Message):
    await message.answer("🤔 Не понимаю. Используйте /start для справки.")

async def main():
    logger.info("Бот запущен и готов к работе!")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())

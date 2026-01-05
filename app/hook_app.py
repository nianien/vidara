#!/usr/bin/env python3
"""
Frida hook 脚本：监听章节列表响应并自动下载 m3u8 视频
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import frida

from app.m3u8_downloader import download_m3u8

from pathlib import Path
from typing import Any
import json


def handle_book(data: Any) -> bool:
    """
    将 book 信息强制写入 downloads/$bookId/book.info
    """
    if not isinstance(data, dict):
        print("[save_book] data is not dict, skip")
        return False

    book_id = data.get("bookId")
    if not book_id:
        print("[save_book] missing bookId, skip")
        return False

    book_dir = Path(__file__).parent.parent / "downloads" / str(book_id)
    book_dir.mkdir(parents=True, exist_ok=True)
    book_info_file = book_dir / "book.info"
    try:
        book_info_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"[save_book] overwrite -> {book_info_file}")
        return True
    except Exception as e:
        print(f"[save_book] write failed: {e}")
        return False


def handle_chapter(data: Any) -> bool:
    if not isinstance(data, list) or len(data) == 0:
        return False

    first_item = data[0] if isinstance(data[0], dict) else {}
    book_id = first_item.get("bookId", "") if isinstance(first_item, dict) else ""
    chapters: Dict[str, str] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        chapter_name = item.get("chapterName")
        cdn = item.get("cdn")
        if not chapter_name or not cdn:
            continue
        chapters[str(chapter_name)] = str(cdn)
    if not book_id or not chapters:
        return
    book_dir = Path(__file__).parent.parent / "downloads" / book_id
    print(f"\n[+] 开始下载 {len(chapters)} 个视频... bookId={book_id}")
    download_m3u8(chapters, book_dir)
    print("[+] 视频下载完成")


def on_message(message, data):
    try:
        # 1) 打完整 message（send / error / log 都会进来）
        print("[FRIDA MESSAGE]", message)

        # 2) 只处理 send
        if message.get("type") != "send":
            return

        payload = message.get("payload") or {}
        if not isinstance(payload, dict):
            return

        msg_type = payload.get("type") or ""
        if not msg_type:
            return

        if msg_type == 'chapter':
            handle_chapter(data)
        elif msg_type == 'book':
            handle_book(data)

    except Exception as e:
        print(f"[!] on_message error: {e}")


def main():
    device = frida.get_usb_device()
    pid = device.spawn(["com.newreading.goodreels"])
    session = device.attach(pid)

    hook_script_path = Path(__file__).parent.parent / "hook" / "hook_chapter.js"
    source = hook_script_path.read_text(encoding="utf-8")
    script = session.create_script(source, runtime="v8")

    script.on("message", on_message)
    script.load()

    device.resume(pid)
    print("[*] 脚本已加载，正在监控数据...")
    input()


if __name__ == "__main__":
    main()

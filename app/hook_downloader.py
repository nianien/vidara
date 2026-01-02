#!/usr/bin/env python3
"""
Frida hook 脚本：监听章节列表响应并自动下载 m3u8 视频
"""

import frida
import json
import subprocess
from pathlib import Path


def _ffmpeg_headers(headers: dict[str, str] | None) -> list[str]:
    """ffmpeg -headers 需要以 CRLF 拼接，并以 CRLF 结尾。"""
    if not headers:
        return []
    header_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n"
    return ["-headers", header_str]


def run_ffmpeg(
        m3u8_url: str,
        output_file: Path,
        headers: dict[str, str] | None = None,
) -> Path:
    """
    用 ffmpeg 直接转封装为 MP4（不重新编码）。
    返回输出文件 Path；失败抛异常。
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        "ffmpeg",
        "-y",
        "-loglevel",
        "error",
        *_ffmpeg_headers(headers),
        "-i",
        m3u8_url,
        "-c",
        "copy",
        str(output_file),
    ]

    print(f"[ffmpeg] start: {m3u8_url} -> {output_file}")
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        raise RuntimeError("未找到 ffmpeg，请先安装（例如：brew install ffmpeg）") from None
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ffmpeg 处理失败（exit={exc.returncode}）") from None

    print(f"[ffmpeg] done: {output_file}")
    return output_file


def parse_url(obj: dict, msg_type: str | None = None) -> dict[str, str]:
    """
    解析请求响应，生成 chapter_name 与 m3u8 url 的映射
    根据不同的 msg_type 处理不同的 JSON 格式

    参数:
        obj: 请求响应JSON 对象
        msg_type: 消息类型，不同的类型对应不同的 JSON 格式
    
    返回:
        dict[str, str]: {chapter_name: video_path} 的映射字典
    """
    url_map = {}

    if msg_type == "goodshort":
        # goodshort 格式: data.list[].chapterName 和 data.list[].cdnList[].videoPath
        # 取第一个存在 videoPath 的内容
        if "data" not in obj or "list" not in obj["data"]:
            return url_map

        for item in obj["data"]["list"]:
            chapter_name = item.get("chapterName")
            if not chapter_name:
                continue

            # 找到第一个存在 videoPath 的 cdnList 项
            cdn_list = item.get("cdnList", [])
            video_path = next((cdn.get("videoPath") for cdn in cdn_list if cdn.get("videoPath")), None)

            if video_path:
                url_map[chapter_name] = video_path
                print(f"[M3U8] {chapter_name}: {video_path}")
    # 可以在这里添加其他类型的处理逻辑
    # elif msg_type == "other_type":
    #     # 处理其他格式的 JSON
    #     pass

    return url_map


def download_m3u8(
        url_map: dict[str, str],
        output_dir: Path,
        headers: dict[str, str] | None = None,
) -> list[Path]:
    """
    批量下载 m3u8 并转封装为 mp4。
    - url_map: {file_name:m3u8_url}，file_name 不需要扩展名，函数自动加 .mp4
    - output_dir: 输出目录，会创建
    返回成功写出的文件列表。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    items = list(url_map.items())
    total = len(items)
    for i, (fname, url) in enumerate(items, start=1):
        out = output_dir / f"{fname}.mp4"

        # 如果文件已存在，跳过
        if out.exists():
            print(f"[batch] [{i}/{total}] skip (已存在) -> {out.name}")
            written.append(out)
            continue

        try:
            print(f"[batch] [{i}/{total}] downloading -> {out.name}")
            run_ffmpeg(url, out, headers=headers)
            written.append(out)
        except Exception as exc:  # noqa: BLE001
            print(f"[x] 失败: {url} -> {exc}")
            continue
    print(f"[batch] finished: {len(written)}/{total} succeeded")
    return written


def on_message(message, data):
    # 1) 先无条件打印：完整 message（包含 type / payload / stack 等）
    print("[FRIDA MESSAGE]", message)

    # 2) 只在 send 时才继续做你的业务逻辑
    if message.get("type") != "send":
        return

    payload = message.get("payload", {})
    if not payload:
        return

    msg_type = payload.get("type", "")
    if not msg_type:
        return

    resp = payload.get("data")
    if not resp:
        return

    try:
        obj = json.loads(resp) if isinstance(resp, str) else resp
    except Exception as e:
        print("[!] json parse failed:", e)
        return

    url_map = parse_url(obj, msg_type)
    if not url_map:
        return

    output_dir = Path(__file__).parent.parent / "downloads"
    print(f"\n[+] 开始批量下载 {len(url_map)} 个视频...")
    download_m3u8(url_map, output_dir)
    print("[+] 批量下载完成")


def main():
    """主函数"""
    # 1. 连接设备与启动
    device = frida.get_usb_device()
    pid = device.spawn(["com.newreading.goodreels"])
    session = device.attach(pid)

    # 2. 加载脚本 (强制指定 V8 运行时)
    hook_script_path = Path(__file__).parent.parent / "frida-compile" / "output" / "hook_chapter.js"
    source = hook_script_path.read_text(encoding="utf-8")
    script = session.create_script(source, runtime="v8")

    script.on("message", on_message)
    script.load()

    # 3. 恢复运行
    device.resume(pid)
    print("[*] 脚本已加载，正在监控数据...")
    input()


if __name__ == "__main__":
    main()

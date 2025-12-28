from __future__ import annotations

"""
工具方法：m3u8 → mp4（ffmpeg copy）& HAR 提取 m3u8 URL

暴露的函数：
- build_ffmpeg_headers(headers) -> list[str]
- run_ffmpeg_m3u8_to_mp4(m3u8_url, output_file, headers=None) -> Path
- batch_download(urls, output_dir, headers=None) -> list[Path]

特点：
- 纯工具方法；调用方可在任意位置 import 使用
- ffmpeg 采用 copy 封装，不重新编码
- 支持可选 headers（会以 CRLF 格式传给 ffmpeg -headers）
"""

import json
import subprocess
from pathlib import Path
from typing import Iterable


def _build_ffmpeg_headers(headers: dict[str, str] | None) -> list[str]:
    """ffmpeg -headers 需要以 CRLF 拼接，并以 CRLF 结尾。"""
    if not headers:
        return []
    header_str = "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n"
    return ["-headers", header_str]


def run_ffmpeg_m3u8_to_mp4(
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
        *_build_ffmpeg_headers(headers),
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


def batch_download(
        url_map: dict[str, str],
        output_dir: Path,
        headers: dict[str, str] | None = None,
) -> list[Path]:
    """
    批量下载 m3u8 并转封装为 mp4。
    - url_map: {m3u8_url: file_name}，file_name 不需要扩展名，函数自动加 .mp4
    - output_dir: 输出目录，会创建
    返回成功写出的文件列表。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    items = list(url_map.items())
    total = len(items)
    for i, (url, fname) in enumerate(items, start=1):
        out = output_dir / f"{fname}.mp4"
        try:
            print(f"[batch] [{i}/{total}] downloading -> {out.name}")
            run_ffmpeg_m3u8_to_mp4(url, out, headers=headers)
            written.append(out)
        except Exception as exc:  # noqa: BLE001
            print(f"[x] 失败: {url} -> {exc}")
            continue
    print(f"[batch] finished: {len(written)}/{total} succeeded")
    return written

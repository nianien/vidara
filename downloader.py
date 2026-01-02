from __future__ import annotations

import sys
from pathlib import Path

import requests


def download_file(url: str, output_path: str) -> Path:
    """
    下载指定 URL 到指定路径（包含文件名）。
    仅用于你有权限下载的资源。
    """
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True, timeout=30) as resp:
        resp.raise_for_status()
        with target.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    return target


def main(argv: list[str]) -> None:
    if len(argv) != 3:
        print("用法: python downloader.py <url> <output_path>")
        print("示例: python downloader.py https://example.com/video.mp4 downloads/myvideo.mp4")
        sys.exit(1)

    url = argv[1]
    output_path = argv[2]

    try:
        saved = download_file(url, output_path)
    except Exception as exc:  # noqa: BLE001
        print(f"下载失败: {exc}")
        sys.exit(1)

    print(f"下载完成: {saved}")


if __name__ == "__main__":
    # 方式一：命令行参数执行（如果需要可以取消注释）
    # main(sys.argv)

    # 方式二：直接在这里写死 URL 和保存文件名，一运行脚本就下载
    # url = "https://video.netshort.com/oAIDpPgtrJMMqCUBfalA251fExwv5KuQAqfFNk?a=0&auth_key=1766456712-21ba33f2cd8c4121b5dabfd7015e493b-0-b68274e484c0eb2345a09bcbc51d8cee&br=1065&bt=1065&cd=0%7C0%7C0&ch=0&cr=0&cs=0&cv=1&dr=0&ds=3&eid=8b80e35bc2c348e6b60c3b49de139ccb&er=0&l=20251213102212F4815F1EC8A9A42B98F1&lr=&mime_type=video_mp4&net=0&pl=0&qs=0&rc=MzhtO3A5cm1mNzozMzZoNEApZjw0Zzc2M2VoN2ZmOGg7O2cybS1kMmQ0ZnJhMi1kXjVzc19gMGI2X2AzMzUwL18wLV86Yw%3D%3D&vl=&vr="
    url="https://v2-akm.goodreels.com/mts/books/861/31001219861/624350/alexzwqv7n/720p/umzfhxpgz1_720p.m3u8?__token__=exp=1768369443~hmac=11685a6935a36b7ad1e45a9cb3cc8e51bfbca77c2ca2974a15ca41ac3158dc46"
    output_path = "test.mp4"

    try:
        saved = download_file(url, output_path)
    except Exception as exc:  # noqa: BLE001
        print(f"下载失败: {exc}")
        sys.exit(1)

    print(f"下载完成: {saved}")


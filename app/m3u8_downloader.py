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


if __name__ == "__main__":
    # 读取 chapter_urls.json
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    json_file = project_root / "chapter_urls.json"
    output_dir = project_root / "downloads" / "test"

    if not json_file.exists():
        print(f"[!] 错误: 找不到文件 {json_file}")
        exit(1)

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            url_map = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] 错误: JSON 解析失败: {e}")
        exit(1)
    except Exception as e:
        print(f"[!] 错误: 读取文件失败: {e}")
        exit(1)

    if not url_map:
        print("[!] 错误: chapter_urls.json 为空")
        exit(1)

    print(f"[+] 读取到 {len(url_map)} 个章节 URL")
    print(f"[+] 输出目录: {output_dir}")

    # 调用 download_m3u8
    try:
        download_m3u8(url_map, output_dir)
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        exit(1)
    except Exception as e:
        print(f"[!] 错误: {e}")
        exit(1)

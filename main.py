from pathlib import Path
from utils.good_short_crawler import GoodShortCrawler
from utils.m3u8_downloader import batch_download

"""
入口脚本：调用 GoodShortCrawler 抓取全集 m3u8。
运行：
    python main.py
"""


def main() -> None:
    # url = "https://www.goodshort.com/episode/eng-dub-beneath-the-rouge-a-sword-31001206527/001-15550270"
    # crawler = GoodShortCrawler(work_root=Path("./downloads"))
    # result = crawler.crawl(start_url=url, show=False, max_limit=12)
    # print(f"done. episodes file: {result.episodes_file}")
    # print(f"total eps: {len(result.episode_urls)} ; captured: {len(result.m3u8_map)}")
    # # 读取 m3u8 列表并下载视频
    # url_map: dict[str, str] = {}
    # for line in result.episodes_file.read_text(encoding="utf-8").splitlines():
    #     line = line.strip()
    #     if not line or "\t" not in line:
    #         continue
    #     ep, u = line.split("\t", 1)
    #     ep_safe = ep.replace(" ", "_")
    #     url_map[u.strip()] = ep_safe
    #
    # if not url_map:
    #     print("[!] m3u8 列表为空，跳过下载")
    #     return
    #
    # out_dir = result.base_dir / "videos"
    # print(f"[+] 开始下载 {len(url_map)} 个视频到 {out_dir}")
    # downloaded = batch_download(url_map, out_dir)
    # print(f"[+] 下载完成：{len(downloaded)}/{len(url_map)}")

    downloaded = batch_download({
                                    "https://zshipricf.farsunpteltd.com/playlet-hls/hls_1762424563_2_37017.m3u8?verify=1766510586-rR6xo4AY36%2Fr9u4kRYJixLyj3zmVwJlqTF8QUhy4jwM%3D": "demo"},
                                Path("./downloads/demo"))


if __name__ == "__main__":
    main()

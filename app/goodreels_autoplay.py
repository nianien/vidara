#!/usr/bin/env python3
"""
GoodReels 自动化播放脚本
一键自动化：打开 GoodReels → 搜索 → 点第一个结果 → 进入播放 → 自动下一集（循环）

前提：
- Appium Server 已运行：appium
- AVD 已启动并解锁
- 包名：com.newreading.goodreels
- Activity：.ui.home.MainActivity

使用方法：
运行：python3 goodreels_autoplay.py
"""

import math
import re
import subprocess
import time
from pathlib import Path

from appium import webdriver
from appium.options.android import UiAutomator2Options
from appium.webdriver.common.appiumby import AppiumBy
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ====== Resource ID 配置 ======
# 主界面搜索入口
SEARCH_ENTRANCE_ID = "com.newreading.goodreels:id/viewClick"  # 搜索入口点击区域
SEARCH_LAYOUT_ID = "com.newreading.goodreels:id/searchLayout"  # 搜索布局容器
SEARCH_ICON_ID = "com.newreading.goodreels:id/ivSearch"  # 搜索图标

# 搜索页元素
SEARCH_EDIT_ID = "com.newreading.goodreels:id/search_edit"
SEARCH_CLEAR_ID = "com.newreading.goodreels:id/search_clear"
SEARCH_RESULTS_ID = "com.newreading.goodreels:id/recycler_view_l"
FIRST_RESULT_IMAGE_ID = "com.newreading.goodreels:id/image"
FIRST_RESULT_TITLE_ID = "com.newreading.goodreels:id/tvBookName"

# 播放页元素
VIDEO_PLAYER_ID = "com.newreading.goodreels:id/videoPlayer"
LIST_BTN_ID = "com.newreading.goodreels:id/iv_episode"

# 剧集列表元素
EPISODE_GRID_ID = "com.newreading.goodreels:id/recyclerView"
EPISODE_INDEX_ID = "com.newreading.goodreels:id/episodeIndex"
EPISODE_LOCKED_ID = "com.newreading.goodreels:id/episodeLocked"

# 底部弹窗元素
BOTTOM_SHEET_ID = "com.newreading.goodreels:id/design_bottom_sheet"
CLOSE_BTN_ID = "com.newreading.goodreels:id/tvClose"
EPISODES_TAB_CONTENT_DESC = "Episodes"

# 解锁相关元素
UNLOCK_RECHARGE_ID = "com.newreading.goodreels:id/unlockRecharge"  # 解锁充值提示

# 解锁相关元素
UNLOCK_RECHARGE_ID = "com.newreading.goodreels:id/unlockRecharge"  # 解锁充值提示

QUERY = "eng dub beneath-the-rouge-a-sword"

# Appium 配置
opts = UiAutomator2Options().load_capabilities({
    "platformName": "Android",
    "automationName": "UiAutomator2",
    "deviceName": "Android",
    "noReset": True,
    "appium:appPackage": "com.newreading.goodreels",
    "appium:appActivity": ".ui.home.MainActivity",
    "appium:newCommandTimeout": 3600,
    # 移除固定端口配置，让 Appium 自动分配端口
    # "appium:systemPort": 8210,
    # "appium:uiautomator2ServerPort": 8211,
})


def tap_pct(driver, x: float, y: float, ms: int = 120) -> None:
    """按百分比坐标点击"""
    w = driver.get_window_size()["width"]
    h = driver.get_window_size()["height"]
    driver.tap([(int(w * x / 100), int(h * y / 100))], ms)


def find_element_safe(driver, by, value, timeout: int = 5):
    """安全查找元素，找不到返回 None"""
    try:
        element = WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )
        return element
    except:
        return None


def measure_row_height(driver) -> int | None:
    """
    运行时测量行高（取 grid 第一个元素的高度）
    返回: 行高（px）或 None（如果测量失败）
    """
    try:
        # 找到 grid 的第一个元素
        items = driver.find_elements(
            AppiumBy.XPATH,
            f"//*[@resource-id='{EPISODE_GRID_ID}']/*[@class='android.view.ViewGroup']"
        )

        if len(items) == 0:
            print("[!] 未找到任何剧集 item，无法测量行高")
            return None

        # 取第一个 item 测量高度
        item = items[0]
        bounds_str = item.get_attribute("bounds")

        if not bounds_str:
            print("[!] 无法获取 item bounds")
            return None

        # 解析 bounds: "[x1,y1][x2,y2]"
        numbers = re.findall(r"\d+", bounds_str)
        if len(numbers) != 4:
            print(f"[!] bounds 格式错误: {bounds_str}")
            return None

        y1, y2 = int(numbers[1]), int(numbers[3])
        height = y2 - y1

        print(f"[+] 测量到行高: {height}px")
        return height
    except Exception as e:
        print(f"[!] 测量行高失败: {e}")
        return None


def is_first_row_visible(driver) -> bool:
    """
    检查第一行是否可见
    判断 grid 中的第一个 episodeIndex 的 text 是否小于等于2
    """
    try:
        # 获取所有可见的 episodeIndex 元素
        all_index_elems = driver.find_elements(AppiumBy.ID, EPISODE_INDEX_ID)

        # 找到第一个可见的 episodeIndex
        for index_elem in all_index_elems:
            try:
                if not index_elem.is_displayed() or not index_elem.text or not index_elem.text.strip():
                    continue
                episode_num = int(index_elem.text)
                if episode_num <= 2:
                    print(f"[+] 起始集数: {episode_num}, 首行可见")
                    return True
                else:
                    print(f"[!] 起始集数: {episode_num}, 首行不可见")
                    return False
            except:
                continue

        # 如果没有找到任何可见的 episodeIndex
        print("[!] 未找到任何可见的 episodeIndex")
        return False
    except Exception as e:
        print(f"[!] 检查首行可见性失败: {e}")
        return False


def scroll_to_first_episode(driver) -> bool:
    """
    滚动到第一集可见
    逻辑：
    1. 滚动后检查第一行是否可见
    2. 判断前两个元素（至少有一个是TextView）的集数是否小于5
    3. 如果不可见，继续向上滚动，直到第一行可见
    """
    try:
        grid = find_element_safe(driver, AppiumBy.ID, EPISODE_GRID_ID, timeout=5)
        if not grid:
            print("[!] 未找到剧集列表 GridView")
            return False

        # 先检查第一行是否已经可见
        if is_first_row_visible(driver):
            print("[+] 第一行已可见，无需滚动")
            return True

        # 如果不可见，向上滚动直到第一行可见
        max_scrolls = 10  # 最多滚动10次
        for i in range(max_scrolls):
            print(f"[+] 第一行不可见，向上滚动 ({i + 1}/{max_scrolls})...")
            try:
                driver.execute_script("mobile: scrollGesture", {
                    "elementId": grid.id,
                    "direction": "up",
                    "percent": 0.5
                })
                time.sleep(0.5)  # 等待滚动完成

                # 检查第一行是否可见
                if is_first_row_visible(driver):
                    print(f"[+] 第一行已可见（滚动 {i + 1} 次）")
                    return True
            except Exception as e:
                print(f"[!] 滚动失败: {e}")
                return False

        print(f"[!] 滚动 {max_scrolls} 次后仍未找到第一行")
        return False
    except Exception as e:
        print(f"[!] 滚动到第一集失败: {e}")
        return False


def adb_input_text(text: str) -> None:
    """使用 adb 输入文本"""
    subprocess.run(["adb", "shell", "input", "text", text], check=False)


def click_search_entrance(driver) -> bool:
    """
    点击主界面的搜索入口
    
    参数:
        driver: Appium WebDriver 实例
    
    返回:
        bool: 如果成功点击返回 True，否则返回 False
    """
    print("[+] 查找主界面搜索入口...")
    search_clicked = False

    # 方法1: 优先查找 viewClick（最直接的点击入口）
    search_entrance = find_element_safe(driver, AppiumBy.ID, SEARCH_ENTRANCE_ID, timeout=5)
    if search_entrance and search_entrance.is_displayed():
        print("[+] 找到搜索入口 viewClick，点击...")
        search_entrance.click()
        search_clicked = True
        time.sleep(1)

    # 方法2: 如果 viewClick 不可用，尝试点击 searchLayout 容器
    if not search_clicked:
        search_layout = find_element_safe(driver, AppiumBy.ID, SEARCH_LAYOUT_ID, timeout=3)
        if search_layout and search_layout.is_displayed():
            print("[+] 找到搜索布局 searchLayout，点击...")
            search_layout.click()
            search_clicked = True
            time.sleep(1)

    # 方法3: 如果都找不到，尝试点击搜索图标
    if not search_clicked:
        search_icon = find_element_safe(driver, AppiumBy.ID, SEARCH_ICON_ID, timeout=2)
        if search_icon and search_icon.is_displayed():
            print("[+] 找到搜索图标 ivSearch，点击...")
            search_icon.click()
            search_clicked = True
            time.sleep(1)

    # 方法4: 最后回退：使用坐标点击（viewClick 的 bounds 约为 [36,120][901,224]，中心点约在 50%, 8%）
    if not search_clicked:
        print("[!] 未找到搜索入口元素，使用坐标点击...")
        tap_pct(driver, 50, 8)
        time.sleep(1)

    return search_clicked


def find_and_click_search_edit(driver):
    """
    查找并点击搜索输入框
    
    参数:
        driver: Appium WebDriver 实例
    
    返回:
        WebElement 或 None: 如果找到搜索输入框返回元素，否则返回 None
    """
    print("[+] 查找搜索输入框...")
    search_edit = find_element_safe(driver, AppiumBy.ID, SEARCH_EDIT_ID, timeout=5)
    if search_edit:
        print("[+] 找到搜索输入框，点击...")
        search_edit.click()
        time.sleep(0.5)
    else:
        print("[!] 未找到搜索输入框，可能已在搜索页或需要等待...")
        time.sleep(1)  # 等待页面加载

    return search_edit


def is_bottom_sheet_open(driver) -> bool:
    """检查底部弹窗是否已打开"""
    try:
        bottom_sheet = find_element_safe(driver, AppiumBy.ID, BOTTOM_SHEET_ID, timeout=1)
        return bottom_sheet is not None and bottom_sheet.is_displayed()
    except:
        return False


def open_episode_list(driver) -> bool:
    """打开剧集列表"""
    # 如果底部弹窗已经打开，检查是否在 Episodes 标签页
    if is_bottom_sheet_open(driver):
        episodes_tab = driver.find_element(
            AppiumBy.XPATH,
            f"//android.widget.LinearLayout[@content-desc='{EPISODES_TAB_CONTENT_DESC}' and @selected='true']"
        )
        if episodes_tab:
            print("[+] 底部弹窗已打开，已在 Episodes 标签页")
            return True

        # 如果不在 Episodes 标签页，点击 Episodes 标签
        episodes_tab = find_element_safe(
            driver,
            AppiumBy.XPATH,
            f"//android.widget.LinearLayout[@content-desc='{EPISODES_TAB_CONTENT_DESC}']",
            timeout=2
        )
        if episodes_tab:
            print("[+] 点击 Episodes 标签...")
            episodes_tab.click()
            time.sleep(0.5)
            return True

    # 播放中时控制栏是隐藏的，需要先点击屏幕唤出控制栏
    print("[+] 点击屏幕唤出控制栏...")
    video_player = find_element_safe(driver, AppiumBy.ID, VIDEO_PLAYER_ID, timeout=2)
    video_player.click()
    time.sleep(0.8)  # 等待控制栏出现

    # 点击 List 按钮（图标按钮 iv_episode）
    print("[+] 点击 List 按钮打开剧集列表...")
    list_btn = WebDriverWait(driver, 3).until(
        EC.element_to_be_clickable((AppiumBy.ID, LIST_BTN_ID))
    )
    list_btn.click()

    # 等待剧集列表 GridView/RecyclerView 出现，确保动画完成
    print("[+] 等待剧集列表加载...")
    WebDriverWait(driver, 5).until(
        EC.presence_of_element_located((AppiumBy.ID, EPISODE_GRID_ID))
    )
    print("[+] 剧集列表已加载")
    time.sleep(0.5)  # 额外等待动画完成
    return True


def check_if_locked(driver) -> bool:
    """
    检查是否需要解锁
    判断是否存在 unlockRecharge 元素
    返回: True 如果需要解锁（未解锁），False 如果正常播放态
    """
    try:
        unlock_elems = driver.find_elements(AppiumBy.ID, UNLOCK_RECHARGE_ID)
        if len(unlock_elems) > 0:
            # 检查是否有可见的解锁元素
            for unlock_elem in unlock_elems:
                if unlock_elem.is_displayed():
                    print("[!] 检测到需要解锁，未解锁状态")
                    return True
        return False
    except Exception as e:
        print(f"[!] 检查解锁状态失败: {e}")
        return False


def swipe_to_next_episode(driver, episode_num: int) -> bool:
    """
    使用上滑手势切换到下一集（最符合实际使用场景）
    参数: episode_num - 要切换到的集数
    返回: 是否成功
    """
    try:
        # 检查并关闭剧集列表（如果打开的话）
        if is_bottom_sheet_open(driver):
            print("[+] 检测到剧集列表已打开，先关闭...")
            close_btn = find_element_safe(driver, AppiumBy.ID, CLOSE_BTN_ID, timeout=2)
            if close_btn:
                close_btn.click()
                time.sleep(1)  # 等待弹窗关闭动画
                print("[+] 已关闭剧集列表")

        size = driver.get_window_size()
        left = int(size["width"] * 0.1)
        top = int(size["height"] * 0.2)
        width = int(size["width"] * 0.8)
        height = int(size["height"] * 0.6)

        print(f"[+] 使用上滑手势切换到第 {episode_num} 集...")
        driver.execute_script("mobile: swipeGesture", {
            "left": left, "top": top, "width": width, "height": height,
            "direction": "up",
            "percent": 0.85
        })
        time.sleep(1)  # 等待切换完成

        # 检查是否需要解锁
        if check_if_locked(driver):
            print(f"[!] 第 {episode_num} 集需要解锁，退出自动播放")
            return False

        print(f"[+] 已切换到第 {episode_num} 集")
        return True
    except Exception as e:
        print(f"[!] 上滑手势失败: {e}")
        return False


def get_book_id_from_file(downloads_dir: Path = None) -> str:
    """
    从 downloads/book_id.txt 文件中读取 book_id
    
    参数:
        downloads_dir: 下载根目录路径，默认为项目根目录下的 downloads
    
    返回:
        str: book_id，如果文件不存在或读取失败返回空字符串
    """
    if downloads_dir is None:
        downloads_dir = Path(__file__).parent.parent / "downloads"

    book_id_file = downloads_dir / "book_id.txt"
    if not book_id_file.exists():
        return ""

    try:
        book_id = book_id_file.read_text(encoding="utf-8").strip()
        return book_id
    except Exception as e:
        print(f"[!] 读取 BookId 失败: {e}")
        return ""


def wait_for_episode_download(episode_index: int, downloads_dir: Path = None, max_wait_time: int = 60) -> bool:
    """
    等待指定集数下载完成
    
    参数:
        episode_index: 集数（从1开始）
        downloads_dir: 下载根目录路径，默认为项目根目录下的 downloads
        max_wait_time: 最大等待时间（秒）
    
    返回:
        bool: 如果下载完成返回 True，超时返回 False
    """
    book_id = get_book_id_from_file(downloads_dir)
    if not book_id:
        print(f"[!] 无法获取 BookId，跳过检查第 {episode_index} 集下载状态")
        return False

    if is_episode_downloaded(episode_index, book_id, downloads_dir):
        return True

    print(f"[!] 第 {episode_index} 集未下载，等待下载完成...")
    wait_interval = 1  # 每5秒检查一次
    waited_time = 0

    while not is_episode_downloaded(episode_index, book_id, downloads_dir):
        if waited_time >= max_wait_time:
            print(f"[!] 等待第 {episode_index} 集下载超时")
            return False
        time.sleep(wait_interval)
        waited_time += wait_interval
    return True


def is_episode_downloaded(episode_index: int, book_id: str, downloads_dir: Path = None) -> bool:
    """
    检查指定集数是否已下载
    
    参数:
        episode_index: 集数（从1开始）
        book_id: 书籍ID，用于确定检查的目录
        downloads_dir: 下载根目录路径，默认为项目根目录下的 downloads
    
    返回:
        bool: 如果已下载返回 True，否则返回 False
    """
    if downloads_dir is None:
        downloads_dir = Path(__file__).parent.parent / "downloads"

    # 视频文件在 downloads/{book_id}/ 目录下
    book_dir = downloads_dir / book_id
    if not book_dir.exists():
        return False

    # 章节名格式：001, 002, 003...
    chapter_name = f"{episode_index:03d}"

    # 检查多种可能的文件名格式
    possible_names = [
        f"{chapter_name}.mp4",  # 001.mp4
        f"{chapter_name}_720p.mp4",  # 001_720p.mp4
        f"{chapter_name}_540p.mp4",  # 001_540p.mp4
        f"{chapter_name}_1080p.mp4",  # 001_1080p.mp4
    ]

    for video_file in possible_names:
        video_path = book_dir / video_file
        if video_path.exists():
            print(f"[+] 第 {episode_index} 集已下载: {video_path}")
            return True

    return False


def click_first_episode(driver) -> bool:
    """打开剧集列表，滚动到第一集可见，然后点击第一集"""
    # 打开剧集列表
    print("[+] 打开剧集列表，定位到第一集...")
    if not open_episode_list(driver):
        print("[!] 打开剧集列表失败")
        return False
    time.sleep(1.5)

    # 滚动到第一集可见
    if not scroll_to_first_episode(driver):
        print("[!] 滚动到第一集失败")
        return False

    time.sleep(0.5)  # 等待滚动完成

    # 重新获取 grid 的所有子元素（滚动后需要重新获取）
    all_containers = driver.find_elements(
        AppiumBy.XPATH,
        f"//*[@resource-id='{EPISODE_GRID_ID}']/*[@class='android.view.ViewGroup']"
    )

    if len(all_containers) == 0:
        print("[!] 未找到任何剧集容器")
        return False

    # 直接取 grid 的第0个元素就是第一集
    first_container = all_containers[0]
    print("[+] 找到第一集容器（grid 的第0个元素）")

    # 使用 driver.find_elements 检查是否锁定
    try:
        locked_elems = driver.find_elements(
            AppiumBy.XPATH,
            f"//*[@resource-id='{EPISODE_LOCKED_ID}']"
        )
        for locked in locked_elems:
            try:
                locked_parent = locked.find_element(
                    AppiumBy.XPATH,
                    "./ancestor::*[@class='android.view.ViewGroup'][@clickable='true'][1]"
                )
                if locked_parent and locked_parent.id == first_container.id and locked.is_displayed():
                    print("[!] 第一集已锁定")
                    return False
            except:
                continue
    except:
        pass

    # 点击第一集
    try:
        print("[+] 找到第一集，点击...")
        first_container.click()
        time.sleep(5)  # 等待视频切换完成

        # 关闭弹窗
        close_btn = find_element_safe(driver, AppiumBy.ID, CLOSE_BTN_ID, timeout=2)
        if close_btn:
            close_btn.click()
            print("[+] 已关闭剧集列表弹窗")
            time.sleep(1)

        return True
    except Exception as e:
        print(f"[!] 点击第一集失败: {e}")
        return False


def main() -> None:
    """主流程"""
    # 连接 Appium
    print("[+] 连接 Appium Server...")
    driver = webdriver.Remote("http://127.0.0.1:4723", options=opts)
    time.sleep(3)

    try:
        # 0) 启动应用（如果还没启动）
        print("[+] 启动应用...")
        try:
            driver.activate_app("com.newreading.goodreels")
            print("[+] 应用已激活")
        except Exception as e:
            print(f"[!] 激活应用失败，尝试启动: {e}")
            try:
                driver.start_activity("com.newreading.goodreels", ".ui.home.MainActivity")
                print("[+] 应用已启动")
            except Exception as e2:
                print(f"[!] 启动应用失败: {e2}，继续尝试...")

        time.sleep(2)  # 等待应用完全加载

        # 1) 点击主界面的搜索入口
        click_search_entrance(driver)

        # 2) 查找并点击搜索输入框（如果已经在搜索页）
        search_edit = find_and_click_search_edit(driver)

        # 2) 清空输入框并输入关键词
        # 先清空（如果有清除按钮）
        clear_btn = find_element_safe(driver, AppiumBy.ID, SEARCH_CLEAR_ID, timeout=2)
        if clear_btn:
            clear_btn.click()
            time.sleep(0.3)

        # 输入关键词并触发搜索
        print(f"[+] 输入搜索关键词: {QUERY}")

        if search_edit:
            # 确保输入框有焦点
            search_edit.click()
            time.sleep(0.2)
            search_edit.clear()
            time.sleep(0.2)
            search_edit.send_keys(QUERY)
            time.sleep(0.5)  # 等待输入完成
        else:
            # 回退：使用 adb 输入
            adb_input_text(QUERY)
            time.sleep(0.5)

        # 触发搜索：点击键盘上的搜索按钮
        # 注意：键盘是系统级组件，通常不在应用 UI hierarchy 中，需要使用坐标点击
        print("[+] 点击键盘搜索按钮...")
        # 使用精确坐标：根据 Appium Inspector 记录的位置 (92.4%, 91.1%)
        tap_pct(driver, 92.4, 91.1)
        time.sleep(0.5)

        # 等待搜索结果加载
        print("[+] 等待搜索结果加载...")
        time.sleep(3)  # 等待搜索结果加载完成

        # 3) 点击第一个搜索结果
        print("[+] 点击第一个搜索结果...")
        episode_found = False

        # 方法1: 通过 RecyclerView 找到第一个结果的封面图（第一个 image）
        results_list = find_element_safe(driver, AppiumBy.ID, SEARCH_RESULTS_ID, timeout=5)
        if results_list:
            # 查找所有封面图，取第一个
            try:
                all_images = driver.find_elements(AppiumBy.ID, FIRST_RESULT_IMAGE_ID)
                if all_images and len(all_images) > 0:
                    first_image = all_images[0]  # 第一个封面图
                    if first_image.is_displayed():
                        print("[+] 找到第一个搜索结果封面图，点击...")
                        first_image.click()
                        episode_found = True
            except Exception as e:
                print(f"[!] 查找封面图失败: {e}")

            # 方法2: 如果封面图点击失败，尝试通过标题查找
            if not episode_found:
                try:
                    # 查找标题包含目标关键词的第一个结果
                    target_title = "[ENG DUB] Beneath the Rouge, A Sword"
                    all_titles = driver.find_elements(AppiumBy.ID, FIRST_RESULT_TITLE_ID)
                    for title in all_titles:
                        if target_title in title.text and title.is_displayed():
                            # 找到标题，点击其父容器（整个结果项）
                            parent = title.find_element(AppiumBy.XPATH, "./..")
                            if parent:
                                print("[+] 通过标题找到第一个搜索结果，点击...")
                                parent.click()
                                episode_found = True
                                break
                except Exception as e:
                    print(f"[!] 通过标题查找失败: {e}")

        # 方法3: 如果都失败，使用坐标点击第一个结果的位置
        if not episode_found:
            print("[!] element 查找失败，使用坐标点击第一个结果...")
            # 第一个结果大约在屏幕上方 15-25% 的位置
            tap_pct(driver, 50, 20)

        time.sleep(2)  # 等待页面加载

        # 4) 打开剧集列表，定位到第一集
        click_first_episode(driver)
        time.sleep(5)  # 等待第一集开始播放

        # 5) 循环：检查当前集是否已下载，然后切换到下一集
        print("[+] 进入自动播放循环...")
        episode_index = 1  # 从第一集开始
        downloads_dir = Path(__file__).parent.parent / "downloads"

        while True:
            # 检查当前集是否已下载，如果未下载则等待
            current_episode = episode_index
            wait_for_episode_download(current_episode, downloads_dir)

            # 当前集已下载，切换到下一集
            episode_index += 1
            print(f"[+] 第 {current_episode} 集已下载，切换到第 {episode_index} 集...")

            # 使用上滑手势切换到下一集
            success = swipe_to_next_episode(driver, episode_index)

            if success:
                time.sleep(5)  # 等待下一集加载并开始播放
            else:
                break  # 退出循环（函数内部已打印失败信息）

    except KeyboardInterrupt:
        print("\n[!] 用户中断")
    except Exception as exc:
        print(f"[x] 错误: {exc}")
    finally:
        driver.quit()
        print("[+] 已断开连接")


if __name__ == "__main__":
    main()

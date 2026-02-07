# -*- coding: utf-8 -*-
#这是图片转文本的主程序
#2025/1/27/20:38
#二次修改于2025/12/20 17:34
#模块版本paddleocr-2.7.0.3 opencv-python-4.6.0.66 paddlepaddle-2.6.2
# pip install numpy==1.26.4
# pip install paddlepaddle==2.6.2
# pip install opencv-python==4.6.0.66
# pip install paddleocr==2.7.0.3
# ©DNE 2026 TNingOCR® 
# --------------------------------------------------------------------
import sys,binascii
import os,secrets
import datetime#,shutil
import time,requests
import threading,struct
import zlib,ctypes
import base64,wmi
import bin_lumtest2 as bin_crypto
import math,json,provemankind4
from typing import Optional, Tuple
import ctypes.wintypes
os.environ["FLAGS_use_mkldnn"] = "0"
os.environ["FLAGS_use_ngraph"] = "0"
VERSION1 = "2.4.1"
VERSIONN = "26.020726p"
from hashlib import pbkdf2_hmac, sha512
from PySide6.QtWidgets import *
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QVariantAnimation, QSettings,QEvent
from PySide6.QtGui import QAction, QIcon, QFont, QTextCursor, QPixmap, QMouseEvent, QColor, QRegion, QImage
from paddleocr import PaddleOCR
import random,string
# import numpy as np
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
UPDATEDIR = os.path.join(os.path.abspath('.'),".dnecache")
UPDATENEWFILE = os.path.join(UPDATEDIR,"versionc.json")
LOG_FILE = os.path.join(os.path.abspath("."), "runlog.log")
FEEDBACK_FILE = os.path.join(os.path.abspath("."), "feedback.json")
ASKFILE = os.path.join(os.path.abspath("."), "tips.bin")
_log_lock = threading.Lock()

def log_event(message: str, level: str = "INFO", print_output: bool = True) -> None:
    """
    记录系统事件到日志文件
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level.upper()}] {message}\n"
    with _log_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8", buffering=1) as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[LOG ERROR] 无法写入日志文件: {e}")
            print(f"[LOG CONTENT] {log_entry.rstrip()}")
            return
    if print_output:
        print(log_entry.rstrip())

def get_setting(key: str, default=None):
    """
    获取设置值
    Args:
        key: 设置键名
        default: 默认值
    Returns:
        设置值
    """
    settings = QSettings()
    if default is not None:
        return settings.value(key, default)
    return settings.value(key)

def startpng(pngpath: str) -> Tuple[str, str]:
    """
    图片转文字
    Args:
        pngpath: 图片路径
    Returns:
        tuple: (用时, 文本)
    """
    output = ""
    start = time.perf_counter()
    # 设置模型路径
    modelrec_dir = None
    modeldet_dir = None
    modelcls_dir = None
    if os.path.exists(os.path.join(os.path.abspath('.'), ".ocrmodels/whl/rec")):
        modelrec_dir = os.path.join(os.path.abspath('.'), ".ocrmodels/whl/rec")
    if os.path.exists(os.path.join(os.path.abspath('.'), ".ocrmodels/whl/det")):
        modeldet_dir = os.path.join(os.path.abspath('.'), ".ocrmodels/whl/det")
    if os.path.exists(os.path.join(os.path.abspath('.'), ".ocrmodels/whl/cls/ch_ppocr_mobile_v2.0_cls_infer")):
        modelcls_dir = os.path.join(os.path.abspath('.'), ".ocrmodels/whl/cls/ch_ppocr_mobile_v2.0_cls_infer")
    try:
        # 读取线程数设置
        settings = QSettings()
        cpu_threads = settings.value("thread_count", 4, type=int)
    except:
        cpu_threads=4
    try:
        ocr = PaddleOCR(
            lang='ch',
            use_gpu=False,
            use_dnn=False,
            use_mkldnn=False,
            enable_mkldnn=False,
            use_angle_cls=True,
            cpu_threads=cpu_threads,
            show_log=False,
            det_model_dir=modeldet_dir,
            rec_model_dir=modelrec_dir,
            cls_model_dir=modelcls_dir
        )
        result = ocr.ocr(pngpath)
        if result is None or len(result) == 0:
            return '0', "未识别到任何文本"
        for line in result:
            for word in line:
                text_line = word[-1]
                text = text_line[0]
                output += text + '\n'
                
        end = time.perf_counter() - start
        return f"{end:.1f}", output
    except Exception as e:
        log_event(f"OCR识别失败: {str(e)}", level="ERROR")
        return "0", f"识别失败: {str(e)}"


def resource_path(relative_path):
    try:
        # PyInstaller创建临时文件夹,将路径存储在_MEIPASS中
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    # 如果路径中包含子目录,确保创建这些目录
    full_path = os.path.join(base_path, relative_path)
    dir_name = os.path.dirname(full_path)
    if not os.path.exists(dir_name) and dir_name:
        os.makedirs(dir_name, exist_ok=True)
    return full_path
def save_feedback(feedback_text: str) -> bool:
    """
    保存反馈到JSON文件
    Args:
        feedback_text: 反馈内容
    Returns:
        bool: 是否保存成功
    """
    if not feedback_text.strip():
        return False
    try:
        # 创建反馈数据
        feedback_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "content": feedback_text.strip()
        }
        # 读取现有反馈或创建新列表
        existing_feedback = []
        if os.path.exists(FEEDBACK_FILE):
            try:
                with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
                    existing_feedback = json.load(f)
                    if not isinstance(existing_feedback, list):
                        existing_feedback = []
            except (json.JSONDecodeError, IOError):
                existing_feedback = []
        # 添加新反馈
        existing_feedback.append(feedback_data)
        # 保存到文件
        with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_feedback, f, ensure_ascii=False, indent=2)
        log_event(f"反馈已保存: \"{feedback_text[:5]}\"...", level="INFO")
        return True
    except Exception as e:
        log_event(f"保存反馈失败: {str(e)}", level="ERROR")
        return False
def iam(x: str) -> str:
    """编码"""
    if not x or not isinstance(x, str):
        return ""
    c = []
    e = []
    v = ''
    for d in x:
        c.append(ord(d) + 3)
    for g in c:
        for h in str(g):
            if int(h) == 0:
                e.append('!')
                e.append('啊')
            else:
                e.append(int(h) * '哦')
                e.append('啊')
        e.append('?')
    for j in e:
        v += j
    return v

def decode(y: str) -> str:
    """解码"""
    if not y or not isinstance(y, str):
        return ""
    result = ""
    c = y.split('?')[:-1]
    for f in c:
        d = f.split('啊')[:-1]
        h = ""
        for g in d:
            if g == '!':
                h += '0'
            else:
                h += str(len(g))
        if h:
            result += chr(int(h) - 3)
    return result

def check_single_instance(app_name: str = "DNE_OCR_App") -> bool:
    """
    检查是否已经有一个实例在运行
    Args:
        app_name: 应用程序唯一名称
    Returns:
        bool: True表示已经有实例在运行 False表示这是第一个实例
    """
    try:
        # 为Windows平台创建命名互斥体
        if sys.platform == 'win32':
            # 创建互斥体句柄
            mutex_name = f"Global\\{app_name}"
            # 定义必要的Windows API
            kernel32 = ctypes.windll.kernel32
            CreateMutex = kernel32.CreateMutexW
            CreateMutex.argtypes = [ctypes.wintypes.LPCVOID, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
            CreateMutex.restype = ctypes.wintypes.HANDLE
            GetLastError = kernel32.GetLastError
            GetLastError.restype = ctypes.wintypes.DWORD
            ERROR_ALREADY_EXISTS = 183
            # 创建互斥体
            mutex = CreateMutex(None, False, mutex_name)
            if mutex:
                # 检查错误代码
                last_error = GetLastError()
                if last_error == ERROR_ALREADY_EXISTS:
                    # 互斥体已经存在,说明程序已经在运行
                    log_event("检测到程序已经在运行", level="WARNING")
                    return True
                else:
                    # 成功创建互斥体这是第一个实例
                    log_event("successmutex", level="INFO")
                    return False
            else:
                # 创建互斥体失败,但允许程序继续运行
                log_event("failmutex1", level="WARNING")
                return False
    except Exception as e:
        log_event(f"mutexcheckfailed: {e}", level="ERROR")
        # 在错误情况下允许程序运行
        return False

def getinfodetail():
    "获取设备详细信息"
    try:
        device = wmi.WMI()
        cpu_info = device.Win32_Processor()
        #processor_id = cpu_info[0].ProcessorId # 直接获取cpu序列号 获取cpu序列号需要花费较长的时间
        name = cpu_info[0].Name # cpu名称
        number_of_cores = cpu_info[0].NumberOfCores # cpu核心数
        thread_count = cpu_info[0].ThreadCount # cpu线程
        disk_info = device.Win32_DiskDrive()[0]
        SSDdata = disk_info.Model
        SSDdata1 = disk_info.Manufacturer
        board_info = device.Win32_BaseBoard()
        board_info1 = board_info[0].Tag
        bios_info = device.Win32_BIOS()
        bios_info1 = bios_info[-1].Version
        bios_info2 = bios_info[0].Name
        computer_info = device.Win32_ComputerSystem()
        computer_info1 = computer_info[0].Name
        # print(name,"\n",number_of_cores,"\n",thread_count,"\n",SSDdata,"\n",SSDdata1,"\n",board_info1,"\n",bios_info1,"\n",bios_info2,"\n",computer_info1)
        r0:str = name+str(number_of_cores)+str(thread_count)+SSDdata+SSDdata1+board_info1+bios_info1+bios_info2+computer_info1
        # s = os.urandom(32).hex()
        # s1 = os.urandom(16).hex()
        result = sha512(sha512(r0.encode()).hexdigest().encode()).hexdigest()
        return result
    except Exception as er:
        log_event(f"错误:{er}",level="ERROR")
        return ""

def messageboxall(title, content, mode):
    """
    通用消息框函数
    Args:
        title: 标题
        content: 内容
        mode: 模式 - "i":信息框, "w":警告框, "e":错误框, "c":确认框
    Returns:
        对于确认框返回用户选择结果
    """
    msg = QMessageBox()
    msg.setWindowTitle(title)
    msg.setText(content)
    msg.setStyleSheet("""
        /* QMessageBox 样式 */
        QMessageBox {
            background-color: #2c3e50;
            border-radius: 10px;
        }
        QMessageBox QLabel {
            color: white;
            font-size: 14px;
            padding: 10px;
        }
        QMessageBox QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
            margin: 5px;
        }
        QMessageBox QPushButton:hover {
            background-color: #45a049;
        }
        QMessageBox QPushButton:pressed {
            background-color: #3d8b40;
        }
        /* 不同类型的按钮样式 */
        QMessageBox QPushButton[text="确定"],
        QMessageBox QPushButton[text="OK"],
        QMessageBox QPushButton[text="Yes"],
        QMessageBox QPushButton[text="是"] {
            background-color: #4CAF50;
        }
        QMessageBox QPushButton[text="取消"],
        QMessageBox QPushButton[text="Cancel"],
        QMessageBox QPushButton[text="No"],
        QMessageBox QPushButton[text="否"] {
            background-color: #f44336;
        }
        QMessageBox QPushButton[text="取消"]:hover,
        QMessageBox QPushButton[text="Cancel"]:hover,
        QMessageBox QPushButton[text="No"]:hover,
        QMessageBox QPushButton[text="否"]:hover {
            background-color: #d32f2f;
        }
        /* 警告框样式 */
        QMessageBox QLabel[text*="警告"],
        QMessageBox QLabel[text*="Warning"] {
            color: #ff9800;
            font-weight: bold;
        }
        /* 错误框样式 */
        QMessageBox QLabel[text*="错误"],
        QMessageBox QLabel[text*="Error"] {
            color: #f44336;
            font-weight: bold;
        }
        /* 信息框样式 */
        QMessageBox QLabel[text*="信息"],
        QMessageBox QLabel[text*="Info"] {
            color: #2196F3;
        }
    """)
    
    # 根据模式设置不同的图标和按钮
    if mode.lower() == "i":  # 信息框
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setDefaultButton(QMessageBox.Ok)
    elif mode.lower() == "w":  # 警告框
        msg.setIcon(QMessageBox.Warning)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setDefaultButton(QMessageBox.Ok)
    elif mode.lower() == "e":  # 错误框
        msg.setIcon(QMessageBox.Critical)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setDefaultButton(QMessageBox.Ok)
    elif mode.lower() == "c":  # 确认框
        msg.setIcon(QMessageBox.Question)
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setDefaultButton(QMessageBox.No)
        # 设置按钮文本为中文
        msg.button(QMessageBox.Yes).setText("是")
        msg.button(QMessageBox.No).setText("否")
    else:  # 默认信息框
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.setDefaultButton(QMessageBox.Ok)
    
    # 对于确认框返回用户选择结果,其他框只显示
    if mode.lower() == "c":
        result = msg.exec()
        return result == QMessageBox.Yes
    else:
        msg.exec()
        return None

class OCRThread(QThread):
    """OCR识别线程"""
    finished = Signal(str, str)  # 用时, 文本
    error = Signal(str)
    
    def __init__(self, image_path: str):
        super().__init__()
        self.image_path = image_path
    
    def run(self):
        try:
            time_taken, text = startpng(self.image_path)
            self.finished.emit(time_taken, text)
        except Exception as e:
            self.error.emit(str(e))


class OCRPage(QWidget):
    """OCR主页面"""
    def __init__(self,user_manager=None):
        super().__init__()
        self.user_manager = user_manager
        self.image_path = ""
        self.content0 = ""
        self.init_ui()
        self.flushask()
        self.update_user_status()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        # title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("DNE - OCR文字识别")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        layout.addWidget(title_frame)
        # self.user_status_label = QLabel("未登录")
        # self.user_status_label.setStyleSheet("""
            # QLabel {
                # color: #ff9800;
                # font-weight: bold;
                # padding: 5px;
                # background-color: #1f2c39;
                # border-radius: 5px;
            # }
        # """)
        # self.user_status_label.setAlignment(Qt.AlignCenter)
        # layout.addWidget(self.user_status_label)
        # 文件选择区域
        file_group = QGroupBox("选择图片")
        file_group.setGraphicsEffect(self.create_shadow())
        file_layout = QVBoxLayout(file_group)
        
        path_layout = QHBoxLayout()
        self.path_label = QLabel("未选择文件")
        self.path_label.setStyleSheet("border: 1px solid #ccc; padding: 5px; background-color: #2c3e50;")
        self.path_label.setWordWrap(True)
        path_layout.addWidget(self.path_label)
        
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.browse_image)
        browse_btn.setMinimumWidth(80)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        path_layout.addWidget(browse_btn)
        file_layout.addLayout(path_layout)
        
        layout.addWidget(file_group)
        
        # 识别控制区域
        control_frame = QFrame()
        # control_frame.setGraphicsEffect(self.create_shadow())
        control_layout = QHBoxLayout(control_frame)
        
        self.recognize_btn = QPushButton("开始识别")
        self.recognize_btn.clicked.connect(self.start_recognition)
        self.recognize_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #ccc;
            }
        """)
        control_layout.addWidget(self.recognize_btn)
        
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(self.copy_result)
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        control_layout.addWidget(copy_btn)
        
        clear_btn = QPushButton("清空结果")
        clear_btn.clicked.connect(self.clear_result)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        control_layout.addWidget(clear_btn)
        self.history_btn = QPushButton("历史记录")
        self.history_btn.clicked.connect(self.show_history)
        self.history_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        self.history_btn.setEnabled(False)  # 默认禁用,登录后启用
        control_layout.addWidget(self.history_btn)
        control_layout.addStretch()
        
        self.time_label = QLabel("")
        self.time_label.setStyleSheet("color: #666; font-weight: bold;")
        control_layout.addWidget(self.time_label)
        
        layout.addWidget(control_frame)
        
        # 结果显示区域
        result_group = QGroupBox("识别结果")
        result_group.setGraphicsEffect(self.create_shadow())
        result_layout = QVBoxLayout(result_group)
        
        self.result_text = QTextEdit()
        self.result_text.setFont(QFont("宋体", 10))
        # self.result_text.setMinimumHeight(100)
        # result_group.setMaximumHeight(260)
        self.result_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 8px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        result_layout.addWidget(self.result_text)
        layout.addWidget(result_group)
        tips_container = QWidget()
        tips_container.setMaximumHeight(50)  # 限制最大高度
        # tips_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)  # 固定高度策略
        tips_container.setStyleSheet("""
            QWidget {
                background-color: #1c2833;
                border-radius: 8px;
            }
        """)
        tips_layout = QHBoxLayout(tips_container)
        tips_layout.setContentsMargins(9, 7, 9, 7)  # 减少内边距
        tips_layout.setSpacing(8)
        
        # 标题Label
        label_b = QLabel("💡 你知道吗:")
        label_b.setFont(QFont("微软雅黑", 9, QFont.Bold))  # 减小字体
        label_b.setStyleSheet("""
            QLabel {
                color: #3498db;
                background-color: transparent;
            }
        """)
        label_b.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        label_b.setFixedWidth(85)  # 固定宽度
        # label_b.setMaximumHeight(30)
        # 内容Label
        self.ask_label = QLabel("")
        self.ask_label.setFont(QFont("微软雅黑", 9))
        # label_b.setMaximumHeight(30)
        self.ask_label.setStyleSheet("""
            QLabel {
                color: #ecf0f1;
                background-color: transparent;
                line-height: 1.1;
            }
        """)
        self.ask_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.ask_label.setWordWrap(True)
        tips_layout.addWidget(label_b)
        tips_layout.addWidget(self.ask_label, 1)  # 为内容Label设置拉伸因子
        layout.addWidget(tips_container)
        # 状态栏
        self.status_label = QLabel("已就绪")
        self.status_label.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        label_b.setMaximumHeight(30)
        self.status_label.setStyleSheet("""
            QLabel {
                padding: 2px;
                background-color: #2c3e50;
                border-radius: 5px;
            }
        """)
        # self.status_label.setMaximumHeight(10)
        layout.addWidget(self.status_label)
    
    def create_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setOffset(0, 0)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(175, 175, 175))
        return shadow
    
    def browse_image(self):
        """浏览并选择图片文件"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "选择图片", "", "图片文件 (*.jpg *.jpeg *.png *.bmp *.gif)"
        )
        
        if filename:
            self.image_path = filename
            self.path_label.setText(filename)
            self.status_label.setText(f"已选择: {os.path.basename(filename)}")
    
    def flushask(self):
        try:
            if not os.path.exists(ASKFILE):
                with open(ASKFILE,'w',encoding='utf-8')as al:
                    al.write("在设置中可以提交反馈,便于我们修复问题\n你可以自己在tip.bin文件中配置更多的'你知道吗'\n如果识别文本复制不了,重新按下'开始识别'再按'复制结果'试试\n如果有什么问题, 可以试试在设置中反馈给我们\n想要新功能? 反馈给我们")
            with open(ASKFILE,'r',encoding='utf-8')as r:
                askbefore = r.readlines()
            askresult = askbefore[secrets.randbelow(len(askbefore)-1)]
            self.ask_label.setText(askresult)
        except Exception as e:
            log_event(str(e),level="Warning")
    
    @Slot(str, str)
    def update_result(self, time_taken: str, text: str):
        """更新识别结果"""
        self.result_text.clear()
        # 保存原始内容
        self.content0 = text
        self.result_text.setPlainText(text)
        self.time_label.setText(f"用时: {time_taken}秒")
        # 计算行数
        line_count = len(text.splitlines())
        self.status_label.setText(f"识别完成 - 共{line_count}行文字")
        # 如果用户已登录,保存历史记录
        if self.user_manager and self.user_manager.current_user:
            self.user_manager.add_history(self.image_path, text, time_taken)
        # 启用按钮
        self.recognize_btn.setEnabled(True)
    
    def update_user_status(self):
        """更新用户状态,启用或禁用历史记录按钮"""
        if self.user_manager and self.user_manager.current_user:
            self.history_btn.setEnabled(True)
            self.history_btn.setStyleSheet("""
                QPushButton {
                    background-color: #9C27B0;
                    color: white;
                    border: none;
                    padding: 8px;
                    border-radius: 8px;
                }
                QPushButton:hover {
                    background-color: #7B1FA2;
                }
            """)
        else:
            self.history_btn.setEnabled(False)
            self.history_btn.setStyleSheet("""
                QPushButton {
                    background-color: #666;
                    color: #999;
                    border: none;
                    padding: 8px;
                    border-radius: 8px;
                }
            """)
    
    def show_history(self):
        """显示历史记录窗口"""
        if self.user_manager and self.user_manager.current_user:
            self.history_window = HistoryWindow(self.user_manager, self)
            screen_geometry = QApplication.primaryScreen().availableGeometry()
            self.history_window.move(
                screen_geometry.center() - self.history_window.rect().center()
            )
            self.history_window.exec()
        else:
            messageboxall("提示", "请先登录以查看历史记录", "i")
    
    def start_recognition(self):
        """开始识别图片文字"""
        if not self.image_path or not os.path.exists(self.image_path):
            messageboxall("警告", "请先选择有效的图片文件!",'w')
            return
        
        # 禁用按钮,防止重复点击
        self.recognize_btn.setEnabled(False)
        self.status_label.setText("识别中...")
        self.time_label.setText("")
        
        # 创建并启动OCR线程
        self.ocr_thread = OCRThread(self.image_path)
        self.ocr_thread.finished.connect(self.update_result)
        self.ocr_thread.error.connect(self.show_error)
        self.ocr_thread.start()
    
    @Slot(str, str)
    def update_result(self, time_taken: str, text: str):
        """更新识别结果"""
        self.result_text.clear()
        # 保存原始内容
        self.content0 = text
        self.result_text.setPlainText(text)
        self.time_label.setText(f"用时: {time_taken}秒")
        # 计算行数
        line_count = len(text.splitlines())
        self.status_label.setText(f"识别完成 - 共{line_count}行文字")
        if self.user_manager and self.user_manager.current_user:
            self.user_manager.add_history(self.image_path, text, time_taken)
        # 启用按钮
        self.recognize_btn.setEnabled(True)
    
    @Slot(str)
    def show_error(self, error_msg: str):
        """显示错误信息"""
        self.result_text.clear()
        self.result_text.setPlainText(error_msg)
        self.time_label.setText("")
        self.status_label.setText("识别失败")
        self.recognize_btn.setEnabled(True)
        log_event(error_msg, level="ERROR")
        messageboxall("错误", error_msg,'e')
    
    def clear_result(self):
        """清空识别结果"""
        self.result_text.clear()
        self.time_label.setText("")
        self.content0 = ""
        self.status_label.setText("已清空结果")
    
    def copy_result(self):
        """复制识别结果"""
        try:
            if not self.content0 or self.content0 == '\n':
                self.status_label.setText("无法复制")
                return
            clipboard = QApplication.clipboard()
            clipboard.setText(self.content0)
            self.status_label.setText("已复制到剪贴板")
        except Exception as e:
            log_event(f"复制失败: {str(e)}", level="ERROR")
            messageboxall("错误", f"无法复制到剪贴板\n{str(e)}",'e')


class AbabPage(QWidget):
    """啊哦文本转换器页面"""
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("啊哦文本转换器")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.back_btn = QPushButton("返回")
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        title_layout.addWidget(self.back_btn)
        
        layout.addWidget(title_frame)
        
        # 编码区域
        encode_group = QGroupBox("编码")
        encode_group.setGraphicsEffect(self.create_shadow())
        encode_layout = QVBoxLayout(encode_group)
        
        encode_layout.addWidget(QLabel("输入要转换的内容"))
        
        self.bian_text = QTextEdit()
        self.bian_text.setFont(QFont("宋体", 10))
        # self.bian_text.setMinimumHeight(120)
        self.bian_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        encode_layout.addWidget(self.bian_text)
        
        encode_btn_layout = QHBoxLayout()
        self.bm_btn = QPushButton("编码")
        self.bm_btn.clicked.connect(self.bianma)
        self.bm_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        encode_btn_layout.addWidget(self.bm_btn)
        encode_btn_layout.addStretch()
        encode_layout.addLayout(encode_btn_layout)
        
        layout.addWidget(encode_group)
        
        # 解码区域
        decode_group = QGroupBox("解码")
        decode_group.setGraphicsEffect(self.create_shadow())
        decode_layout = QVBoxLayout(decode_group)
        
        decode_layout.addWidget(QLabel("输入要解码的内容"))
        
        self.jie_text = QTextEdit()
        self.jie_text.setFont(QFont("宋体", 10))
        # self.jie_text.setMinimumHeight(120)
        self.jie_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        decode_layout.addWidget(self.jie_text)
        
        decode_btn_layout = QHBoxLayout()
        self.jm_btn = QPushButton("解码")
        self.jm_btn.clicked.connect(self.jiema)
        self.jm_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        decode_btn_layout.addWidget(self.jm_btn)
        decode_btn_layout.addStretch()
        decode_layout.addLayout(decode_btn_layout)
        
        layout.addWidget(decode_group)
        
        layout.addStretch()
    
    def create_shadow(self):
        """创建阴影效果"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)
        return shadow
    
    @Slot()
    def bianma(self):
        """编码"""
        b = self.bian_text.toPlainText()
        messageboxall("操作进行中", "正在编码中",'i')
        res = iam(b)
        self.jie_text.clear()
        self.jie_text.setPlainText(res)
    
    @Slot()
    def jiema(self):
        """解码"""
        j = self.jie_text.toPlainText()
        messageboxall("操作进行中", "正在解码中",'i')
        r = decode(j)
        self.bian_text.clear()
        self.bian_text.setPlainText(r)


class TextCompressorPage(QWidget):
    """文本压缩解压工具页面"""
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("文本压缩器")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.back_btn = QPushButton("返回")
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        title_layout.addWidget(self.back_btn)
        
        layout.addWidget(title_frame)
        
        # 主内容区域
        main_layout = QVBoxLayout()
        
        # 原始文本区域
        input_group = QGroupBox("原始文本")
        input_group.setGraphicsEffect(self.create_shadow())
        input_layout = QVBoxLayout(input_group)
        
        self.input_text = QTextEdit()
        self.input_text.setFont(QFont("宋体", 10))
        # self.input_text.setMinimumHeight(150)
        self.input_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        input_layout.addWidget(self.input_text)
        
        main_layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        compress_btn = QPushButton("压缩文本")
        compress_btn.clicked.connect(self.compress_text)
        compress_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        button_layout.addWidget(compress_btn)
        
        decompress_btn = QPushButton("解压文本")
        decompress_btn.clicked.connect(self.decompress_text)
        decompress_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(decompress_btn)
        
        button_layout.addStretch()
        
        clear_btn = QPushButton("清空全部")
        clear_btn.clicked.connect(self.clear_all)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        button_layout.addWidget(clear_btn)
        
        main_layout.addLayout(button_layout)
        
        # 压缩结果区域
        output_group = QGroupBox("压缩结果")
        output_group.setGraphicsEffect(self.create_shadow())
        output_layout = QVBoxLayout(output_group)
        
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("宋体", 10))
        # self.output_text.setMinimumHeight(150)
        self.output_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        output_layout.addWidget(self.output_text)
        
        main_layout.addWidget(output_group)
        
        # 状态信息区域
        info_layout = QHBoxLayout()
        
        self.size_label = QLabel("原始大小: 0 字节")
        self.size_label.setStyleSheet("color: #666;")
        info_layout.addWidget(self.size_label)
        
        self.compressed_label = QLabel("压缩后: 0 字节")
        self.compressed_label.setStyleSheet("color: #666;")
        info_layout.addWidget(self.compressed_label)
        
        self.ratio_label = QLabel("压缩率: 0%")
        self.ratio_label.setStyleSheet("color: #666;")
        info_layout.addWidget(self.ratio_label)
        
        info_layout.addStretch()
        main_layout.addLayout(info_layout)
        
        self.ifo_label = QLabel("注意: 解压文本将会把'压缩结果'区域的内容解压至'原始文本'区域\n短文本的压缩效果可能不理想")
        self.ifo_label.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.ifo_label.setStyleSheet("""
            QLabel {
                padding: 5px;
                background-color: #2c3e50;
                border-radius: 3px;
                color:rgb(202, 81, 81);
            }
        """)
        main_layout.addWidget(self.ifo_label)
        # 状态栏
        self.status_label = QLabel("准备就绪")
        self.status_label.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.status_label.setStyleSheet("""
            QLabel {
                padding: 3px;
                background-color: #2c3e50;
                border-radius: 3px;
            }
        """)
        main_layout.addWidget(self.status_label)
        
        layout.addLayout(main_layout)
    
    def create_shadow(self):
        """创建阴影效果"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)
        return shadow
    
    @Slot()
    def compress_text(self):
        """压缩文本"""
        text = self.input_text.toPlainText().strip()
        if not text:
            self.status_label.setText("请输入要压缩的文本")
            return
        
        try:
            # 压缩
            compressed_bytes = zlib.compress(text.encode('utf-8'), level=9)
            compressed_str = base64.b64encode(compressed_bytes).decode('utf-8')
            
            # 显示结果
            self.output_text.clear()
            self.output_text.setPlainText(compressed_str)
            
            # 更新统计信息
            orig_size = len(text.encode('utf-8'))
            comp_size = len(compressed_str.encode('utf-8'))
            ratio = (1 - comp_size / orig_size) * 100
            
            self.size_label.setText(f"原始大小: {orig_size:,} 字节")
            self.compressed_label.setText(f"压缩后: {comp_size:,} 字节")
            self.ratio_label.setText(f"压缩率: {ratio:.1f}%")
            
            self.status_label.setText("压缩完成")
            
        except Exception as e:
            self.status_label.setText(f"压缩失败: {str(e)}")
    
    @Slot()
    def decompress_text(self):
        """解压文本"""
        text = self.output_text.toPlainText().strip()
        if not text:
            self.status_label.setText("请输入要解压的文本")
            return
        
        try:
            # 解压
            compressed_bytes = base64.b64decode(text)
            decompressed_bytes = zlib.decompress(compressed_bytes)
            decompressed_str = decompressed_bytes.decode('utf-8')
            
            # 显示结果
            self.input_text.clear()
            self.input_text.setPlainText(decompressed_str)
            
            # 更新统计信息
            comp_size = len(text.encode('utf-8'))
            decomp_size = len(decompressed_str.encode('utf-8'))
            
            self.size_label.setText(f"压缩大小: {comp_size:,} 字节")
            self.compressed_label.setText(f"解压后: {decomp_size:,} 字节")
            self.ratio_label.setText("解压完成")
            
            self.status_label.setText("解压完成")
            
        except Exception as e:
            self.status_label.setText(f"解压失败: {str(e)}")
            log_event(f"解压失败: {str(e)}", level="ERROR")
    
    @Slot()
    def clear_all(self):
        """清空所有内容"""
        self.input_text.clear()
        self.output_text.clear()
        self.size_label.setText("原始大小: 0 字节")
        self.compressed_label.setText("压缩后: 0 字节")
        self.ratio_label.setText("压缩率: 0%")
        self.status_label.setText("已清空")


class SettingsPage(QWidget):
    """设置页面"""
    def __init__(self):
        super().__init__()
        self.update_thread = None  # 添加更新线程引用
        self.autoupdate_thread = None
        self.settings = QSettings()
        self.init_ui()
        self.updatethread()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("设置")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.back_btn = QPushButton("返回")
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        title_layout.addWidget(self.back_btn)
        
        layout.addWidget(title_frame)
        
        # 设置内容区域
        self.settings_group = QGroupBox("系统设置")
        self.settings_group.setGraphicsEffect(self.create_shadow())
        settings_layout = QVBoxLayout(self.settings_group)
        
        # 关于按钮
        about_btn = QPushButton("关于")
        about_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        about_btn.clicked.connect(self.show_about)
        settings_layout.addWidget(about_btn)
        
        # 高级设置按钮
        advanced_btn = QPushButton("高级设置")
        advanced_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        advanced_btn.clicked.connect(self.show_advanced_settings)
        settings_layout.addWidget(advanced_btn)
        
        self.ckupdate_btn = QPushButton("检查更新")
        self.ckupdate_btn.setStyleSheet("""
            QPushButton {
                background-color: #AD4AB1;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #945896;
            }
        """)
        self.ckupdate_btn.clicked.connect(self.checkupdate)
        settings_layout.addWidget(self.ckupdate_btn)
        
        # 更新状态标签
        # self.update_status_label = QLabel("")
        # self.update_status_label.setStyleSheet("color: #888; font-size: 12px; padding-left: 10px;")
        # settings_layout.addWidget(self.update_status_label)
        
        # 退出按钮
        exit_btn = QPushButton("退出程序")
        exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        exit_btn.clicked.connect(self.exit_app)
        settings_layout.addWidget(exit_btn)
        layout.addWidget(self.settings_group)
        # 反馈区域 移动到设置组内
        feedback_group = QGroupBox("用户反馈")
        feedback_layout = QVBoxLayout(feedback_group)
        
        self.feedback_edit = QLineEdit()
        self.feedback_edit.setPlaceholderText("请输入反馈,按回车键提交")
        self.feedback_edit.setClearButtonEnabled(True)
        self.feedback_edit.returnPressed.connect(self.save_feedback)  # 回车键提交
        
        feedback_layout.addWidget(QLabel("我们会尽快对反馈做出回应"))
        feedback_layout.addWidget(self.feedback_edit)
        
        # 反馈状态标签
        self.feedback_status_label = QLabel("")
        self.feedback_status_label.setStyleSheet("color: #888; font-size: 12px;")
        feedback_layout.addWidget(self.feedback_status_label)
        
        settings_layout.addWidget(feedback_group)
        # 版本信息
        version_label = QLabel(f"版本: {VERSION1}\n内部版本: {VERSIONN}")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("color: #666; font-size: 12px; margin-top: 20px;")
        layout.addWidget(version_label)
        layout.addStretch()
    
    def create_shadow(self):
        """创建阴影效果"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)
        return shadow
    
    def checkupdate(self):
        """检查更新"""
        # self.update_status_label.setText("正在检查更新...")
        # self.update_status_label.setStyleSheet("color: #2196F3; font-size: 12px; padding-left: 10px;")
        
        # 禁用更新按钮,防止重复点击
        for i in range(self.settings_group.layout().count()):
            widget = self.settings_group.layout().itemAt(i).widget()
            if isinstance(widget, QPushButton) and widget.text() == "检查更新":
                self.ckupdate_btn.setStyleSheet("""
            QPushButton {
                background-color: #494848;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }""")
                widget.setEnabled(False)
                break
        
        # 创建并启动更新线程
        self.update_thread = UpdateThread()
        self.update_thread.update_downloaded.connect(self.on_update_downloaded)
        self.update_thread.finished.connect(self.on_update_finished)
        self.update_thread.start()
    
    @Slot(str)
    def on_update_downloaded(self, file_path):
        """更新文件下载成功"""
        try:
            if file_path[:2] == "ER":
                messageboxall("更新失败",f"错误:{file_path[3:]}",'e')
            # 读取下载的版本信息
            with open(file_path, 'r', encoding='utf-8') as f:
                update_data = json.load(f)
            new_version = update_data.get("version", "未知版本")
            # 显示成功消息框
            # print(new_version,'before')
            try:
                new_v=new_version.replace('.','')
                new_v=int(new_v)
            except:
                new_v=0
            nowv = VERSION1.replace('.','')
            try:
                nowv=int(nowv)
            except:
                nowv=0
            # print(new_version,nowv)
            if new_v > nowv:
                msg_box = QMessageBox(self)
                msg_box.setIcon(QMessageBox.Information)
                msg_box.setWindowTitle("检查更新")
                msg_box.setText(f"发现新版本!\n\n最新版本: {new_version}\n点击ok将自动安装更新，重启程序后生效")
                msg_box.setStandardButtons(QMessageBox.Ok)
                # 添加自定义按钮查看文件
                # view_btn = msg_box.addButton("查看文件", QMessageBox.ActionRole)
                
                if msg_box.exec() == QMessageBox.Ok:
                    # 用户点击了确定
                    pass
                # self.update_status_label.setText("发现新版本!")
                # self.update_status_label.setStyleSheet("color: #4CAF50; font-size: 12px; padding-left: 10px;")
                # elif msg_box.clickedButton() == view_btn:
                    # 查看文件
                    # try:
                        # os.startfile(file_path)  # Windows
                    # except Exception as ee:
                        # log_event(str(ee),level="ERROR")
            else:
                messageboxall("检查更新","当前已是最新版",'i')
                # self.update_status_label.setText("无可用新版本")
                # self.update_status_label.setStyleSheet("color: yellow; font-size: 12px; padding-left: 10px;")
            
        except Exception as e:
            log_event(f"处理更新文件失败: {e}", level="ERROR")
            messageboxall("更新检查", f"下载成功但处理失败: {e}",'e')
            # self.update_status_label.setText("处理更新信息失败")
            # self.update_status_label.setStyleSheet("color: #FF9800; font-size: 12px; padding-left: 10px;")
    
    @Slot()
    def on_update_finished(self):
        """更新线程结束"""
        # 启用更新按钮
        for i in range(self.settings_group.layout().count()):
            widget = self.settings_group.layout().itemAt(i).widget()
            if isinstance(widget, QPushButton) and widget.text() == "检查更新":
                widget.setEnabled(True)
                self.ckupdate_btn.setStyleSheet("""
            QPushButton {
                background-color: #AD4AB1;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 14px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: #945896;
            }""")
                break
    def autoudownloaded(self,message):
        "更新中"
        m=message[:3]
        try:
            if m == "ER":
                messageboxall("更新失败",f"错误:{m}",'e')
                return
            with open(message, 'r', encoding='utf-8') as f:
                update_data = json.load(f)
            new_version = update_data.get("version", "未知版本")
            try:
                new_v=new_version.replace('.','')
                new_v=int(new_v)
            except:
                new_v=0
            nowv = VERSION1.replace('.','')
            try:
                nowv=int(nowv)
            except:
                nowv=0
            if new_v > nowv:
                msg_box = QMessageBox(self)
                msg_box.setIcon(QMessageBox.Information)
                msg_box.setWindowTitle("检查更新")
                msg_box.setText(f"发现新版本!\n\n最新版本: {new_version}")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
                if msg_box.exec() == QMessageBox.Ok:
                    pass
        except Exception as e:
            log_event(f"处理更新文件失败: {e}", level="ERROR")
            QMessageBox.warning(self, "更新检查", f"下载成功但处理失败: {e}")
    def autoufinished(self):
        "更新结束"
        pass
    def updatethread(self):
        "多线程检查更新"
        # self.autoupdate_thread = UpdateThread()
        # self.autoupdate_thread.update_downloaded.connect(self.autoudownloaded)
        # self.autoupdate_thread.finished.connect(self.autoufinished)
        # self.autoupdate_thread.start()
        try:
            # 读取自动检查更新设置,默认为True
            auto_update = self.settings.value("auto_update", True, type=bool)
            
            if not auto_update:
                log_event("自动检查更新已关闭,跳过更新检查", level="INFO")
                return  # 如果设置为关闭,则不自动检查更新
            
            log_event("开始自动检查更新", level="INFO")
            self.autoupdate_thread = UpdateThread()
            self.autoupdate_thread.update_downloaded.connect(self.autoudownloaded)
            self.autoupdate_thread.finished.connect(self.autoufinished)
            self.autoupdate_thread.start()
            
        except Exception as e:
            log_event(f"读取自动更新设置失败: {str(e)}", level="ERROR")
            # 出错时默认执行更新检查
            self.autoupdate_thread = UpdateThread()
            self.autoupdate_thread.update_downloaded.connect(self.autoudownloaded)
            self.autoupdate_thread.finished.connect(self.autoufinished)
            self.autoupdate_thread.start()
    
    @Slot()
    def save_feedback(self):
        "保存用户反馈"
        feedback_text = self.feedback_edit.text().strip()
        
        if not feedback_text:
            self.feedback_status_label.setText("反馈内容不能为空")
            self.feedback_status_label.setStyleSheet("color: #f44336; font-size: 12px;")
            return
        
        if save_feedback(feedback_text):
            self.feedback_status_label.setText("反馈已保存")
            self.feedback_status_label.setStyleSheet("color: #4CAF50; font-size: 12px;")
            self.feedback_edit.clear()
            
            # 3秒后清空状态消息
            QTimer.singleShot(3000, lambda: self.feedback_status_label.setText(""))
        else:
            self.feedback_status_label.setText("保存失败, 请稍后重试")
            self.feedback_status_label.setStyleSheet("color: #f44336; font-size: 12px;")
    @Slot()
    def show_about(self):
        """显示关于对话框"""
        messageboxall(
            "关于 DNE - OCR文字识别",
            f"开发者qq: 3696613574\n版本: {VERSION1}\n内部版本: {VERSIONN}",'i')
    
    @Slot()
    def show_advanced_settings(self):
        """显示高级设置页面"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("警告")
        msg_box.setText("高级设置包含可能影响程序稳定性的选项, 真的要继续吗")
        # 添加自定义按钮
        custom_button = msg_box.addButton("我知道我在做什么!", QMessageBox.AcceptRole)
        cancel_button = msg_box.addButton(QMessageBox.Cancel)
        custom_button.setStyleSheet("""
        QPushButton {
                color: red;
        }
        """)
        # 设置默认按钮
        msg_box.setDefaultButton(cancel_button)
        # 显示对话框
        msg_box.exec()
        # 检查用户点击了哪个按钮
        if msg_box.clickedButton() == custom_button:
            # 发出信号让主窗口显示高级设置页面
            self.advanced_settings_requested.emit()
    
    @Slot()
    def exit_app(self):
        """退出程序"""
        reply = QMessageBox.question(
            self,
            "确认退出",
            "确定要退出程序吗",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # 发出信号让主窗口退出
            self.exit_requested.emit()
    
    # 定义信号
    advanced_settings_requested = Signal()
    exit_requested = Signal()

class UpdateThread(QThread):
    """更新检查线程"""
    update_downloaded = Signal(str)
    
    def __init__(self):
        super().__init__()
        # self.run()
    
    def run(self):
        """运行更新检查"""
        try:
            os.makedirs(UPDATEDIR, exist_ok=True)
            response = requests.get("https://gh-proxy.org/https://github.com/dream863/versionudr/blob/main/versionc.json", timeout=21)
            response.raise_for_status()
            with open(UPDATENEWFILE, 'w', encoding='utf-8') as f:
                f.write(response.text)
            log_event("updatedownSuccess", level="INFO")
            # 发送成功信号携带文件路径
            with open(UPDATENEWFILE, 'r', encoding='utf-8') as ff:
                update_data = json.load(ff)
            self.new_version = update_data.get("version", "0")
            try:
                new_v=self.new_version.replace('.','')
                new_v=int(new_v)
            except:
                new_v=0
            nowv = VERSION1.replace('.','')
            try:
                nowv=int(nowv)
            except:
                nowv=0
            # print(new_v,nowv)
            if new_v > nowv:
                response = requests.get(f"https://gh-proxy.org/https://github.com/dream863/versionudr/blob/main/{self.new_version}.py", timeout=21)
                response.raise_for_status()
                with open(os.path.join(UPDATEDIR,f"{self.new_version}.py"),'w',encoding='utf-8')as p:
                    p.write(response.text)
                self.change()#处理
            self.update_downloaded.emit(UPDATENEWFILE)
        except requests.exceptions.HTTPError as er:
            self.update_downloaded.emit(f"ER{er}")
            log_event(f"下载失败: HTTP错误 {er.response.status_code}", level="ERROR")
        except requests.exceptions.RequestException as ee:
            self.update_downloaded.emit(f"ER{ee}")
            # QMessageBox.warning(self, "更新检查", f"下载成功但处理失败: {ee}")
            log_event(f"下载失败: 网络错误 {ee}", level="ERROR")
        except Exception as e:
            self.update_downloaded.emit(f"ER{e}")
            log_event(f"下载失败: {e}", level="ERROR")
    def change(self):
        newpy = os.path.join(UPDATEDIR,f"{self.new_version}.py")
        newbat = os.path.join(os.path.abspath('.'),"启动.bat")
        pd=os.path.getsize(newpy)
        if not os.path.exists(newpy) or pd <= 181780:
            log_event("找不到用于更新的源文件",level="ERROR")
            return
        try:
            with open(newbat,'w')as bat:
                bat.write(f"@echo off\nset \"pyp=%~dp0\.venv\Scripts\python.exe\"\n%pyp% \"{newpy}\"")
                log_event("更新已完成")
        except Exception as r:
            log_event(f"{r}",level="ERROR")

class UserManager:
    """用户管理器"""
    def __init__(self):
        self.users_file = os.path.join(os.path.abspath("."), "users.json")
        self.session_file = os.path.join(os.path.abspath("."), "session.json")
        self.current_user = None
        self.load_users()
        self.load_session()
    
    def load_users(self):
        """加载用户数据"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def load_session(self):
        """加载上次登录的会话"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                    username = session_data.get("username", "")
                    # 可以添加更多验证,比如验证token或过期时间
                    # 换设备自动退出登录.
                    settings = QSettings("ocrdne", "setusr")
                    # settings.setIniCodec("UTF-8")
                    ifo = settings.value("tag","")
                    if username and ifo == getinfodetail():
                        # 简单恢复登录状态
                        self.current_user = username
                        # log_event(f"自动恢复用户会话: {username}", level="INFO")
                    elif ifo == '0' or ifo == "":
                        return
                    else:
                        print(ifo)
                        messageboxall("提醒","设备已更改,当前用户已自动登出",'w')
        except Exception as e:
            log_event(f"加载会话失败: {str(e)}", level="ERROR")
    
    def save_session(self):
        """保存当前会话"""
        try:
            session_data = {
                "username": self.current_user if self.current_user else "",
                "timestamp": datetime.datetime.now().isoformat()
            }
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
            settings = QSettings("ocrdne", "setusr")
            # settings.setIniCodec("UTF-8")
            settings.remove("tag")
            settings.setValue("tag",getinfodetail())
        except Exception as e:
            log_event(f"保存会话失败: {str(e)}", level="ERROR")
    
    def save_users(self, users):
        """保存用户数据"""
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(users, f, ensure_ascii=False, indent=2)
            return True
        except:
            return False
    # def save_users(self, users):
    #     """保存用户数据，添加版本和校验"""
    #     try:
    #         # 为每个用户添加版本和校验
    #         for username, user_data in users.items():
    #             # 添加数据版本
    #             # user_data['_version'] = 'v2'  # 新版本
    #             user_data['_created'] = datetime.datetime.now().isoformat()
                
    #             # 创建数据校验码
    #             check_data = f"{username}:{user_data['password']}:{user_data['salt']}"
    #             check_code = sha512(check_data.encode()).hexdigest()[:16]
    #             user_data['_checksum'] = check_code
            
    #         with open(self.users_file, 'w', encoding='utf-8') as f:
    #             json.dump(users, f, ensure_ascii=False, indent=2)
    #         return True
    #     except Exception as e:
    #         log_event(f"保存用户数据失败: {str(e)}", level="ERROR")
    #         return False

    # def verify_user_data(self, username, user_data):
    #     """验证用户数据完整性"""
    #     if '_checksum' not in user_data:
    #         return False  # 旧数据或无校验
    #     expected_check = f"{username}:{user_data['password']}:{user_data['salt']}"
    #     expected_code = sha512(expected_check.encode()).hexdigest()[:16]
    #     return user_data['_checksum'] == expected_code
    def _hash_password(self, password: str, salt: bytes = None) -> tuple:
        """
        使用PBKDF2_HMAC和盐值加密密码
        Args:
            password: 原始密码
            salt: 盐值如果为None则生成新盐值
        Returns:
            tuple: (哈希后的密码, 盐值)
        """
        if salt is None:
            salt = secrets.token_bytes(16)  # 生成16字节的随机盐值
        
        # 使用PBKDF2_HMAC进行密码哈希,迭代次数为100000
        hash_result = pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            100000,
            dklen=32
        )
        
        # 将二进制结果转换为十六进制字符串
        hash_hex = binascii.hexlify(hash_result).decode('utf-8')
        salt_hex = binascii.hexlify(salt).decode('utf-8')
        
        return hash_hex, salt_hex
    
    def _verify_password(self, password: str, stored_hash: str, salt_hex: str) -> bool:
        """
        验证密码
        Args:
            password: 待验证的密码
            stored_hash: 存储的哈希值
            salt_hex: 存储的盐值(十六进制字符串)
        Returns:
            bool: 密码是否正确
        """
        try:
            # 将十六进制盐值转换为字节
            salt = binascii.unhexlify(salt_hex)
            
            # 使用相同的参数计算哈希值
            hash_result = pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000,
                dklen=32
            )
            
            hash_hex = binascii.hexlify(hash_result).decode('utf-8')
            
            # 使用恒定时间比较,防止时序攻击
            return secrets.compare_digest(hash_hex, stored_hash)
        except Exception as e:
            log_event(f"密码验证失败: {str(e)}", level="ERROR")
            return False
    
    def register(self, username, password, mouse_random=None):
        """注册新用户"""
        users = self.load_users()
        if username in users:
            return False, "用户名已存在"
        # 验证用户名和密码
        if len(username) < 3:
            return False, "用户名至少需要3个字符"
        if len(password) < 6:
            return False, "密码至少需要6个字符"
        # 生成盐值
        salt = secrets.token_bytes(16)
        # 如果提供了鼠标随机数，将其与盐值结合
        if mouse_random:
            try:
                # 将鼠标随机数与盐值结合
                mouse_bytes = binascii.unhexlify(mouse_random[:32])  # 取前32字节
                combined_salt = salt + mouse_bytes
                # 使用PBKDF2_HMAC进行密码哈希，迭代次数为100000
                hash_result = pbkdf2_hmac(
                    'sha256', 
                    password.encode('utf-8'), 
                    combined_salt, 
                    100000,
                    dklen=32
                )
                # 将二进制结果转换为十六进制字符串
                hash_hex = binascii.hexlify(hash_result).decode('utf-8')
                salt_hex = binascii.hexlify(combined_salt).decode('utf-8')
                log_event(f"用户注册:{username}", level="INFO")
            except Exception as e:
                log_event(f"使用鼠标随机数失败,使用普通注册: {str(e)}", level="WARNING")
                # 回退到普通注册
                hash_hex, salt_hex = self._hash_password(password)
        else:
            # 普通注册(没有鼠标随机数)
            hash_hex, salt_hex = self._hash_password(password)
        users[username] = {
            "password": hash_hex,
            "salt": salt_hex,
            "history": [],
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": None,
            "enhanced_security": mouse_random is not None  # 标记是否使用了增强安全
        }
        if self.save_users(users):
            log_event(f"用户注册成功: {username}", level="INFO")
            return True, "注册成功"
        return False, "注册失败"
    
    def login(self, username, password):
        """用户登录"""
        users = self.load_users()
        if username not in users:
            # 为了防止用户枚举攻击这里进行虚拟验证
            self._dummy_verify()
            return False, "用户名或密码错误"
        user_data = users[username]
        stored_hash = user_data.get("password", "")
        salt = user_data.get("salt", "")
        # 如果没有salt字段说明是新用户系统应该使用新方法
        if not salt:
            return False, "用户数据异常,请联系管理员"
        # 验证密码
        if self._verify_password(password, stored_hash, salt):
            self.current_user = username
            self.save_session()
            # 更新最后登录时间
            users[username]["last_login"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.save_users(users)
            log_event(f"用户登录成功: {username}", level="INFO")
            return True, "登录成功"
        return False, "用户名或密码错误"
    
    def _dummy_verify(self):
        """虚拟验证,用于防止时序攻击"""
        # 创建一个虚拟哈希进行验证,确保无论用户是否存在,响应时间都一致
        dummy_password = secrets.token_urlsafe(16)
        dummy_salt = secrets.token_bytes(16)
        dummy_hash = pbkdf2_hmac(
            'sha256',
            dummy_password.encode('utf-8'),
            dummy_salt,
            100000,
            dklen=32
        )
        # 与自身比较(总是返回True,但消耗时间)
        secrets.compare_digest(binascii.hexlify(dummy_hash).decode('utf-8'), binascii.hexlify(dummy_hash).decode('utf-8'))
    
    def logout(self):
        """用户登出"""
        self.current_user = None
        self.save_session()
        settings = QSettings("ocrdne", "setusr")
        settings.remove("tag")
        settings.setValue("tag",'0')
    
    def add_history(self, image_path, text, time_taken):
        """添加用户历史记录"""
        if not self.current_user:
            return
        
        users = self.load_users()
        if self.current_user in users:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            history_entry = {
                "timestamp": timestamp,
                "image_path": image_path,
                "text": text,
                "time_taken": time_taken
            }
            
            # 只保留最近50条记录
            users[self.current_user].setdefault("history", [])
            users[self.current_user]["history"].insert(0, history_entry)
            if len(users[self.current_user]["history"]) > 50:
                users[self.current_user]["history"] = users[self.current_user]["history"][:50]
            
            self.save_users(users)
    
    def get_history(self):
        """获取当前用户的历史记录"""
        if not self.current_user:
            return []
        
        users = self.load_users()
        return users.get(self.current_user, {}).get("history", [])


class DifficultCaptchaDialog(QDialog):
    """操作验证对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("操作验证")
        self.setFixedSize(450, 350)
        self.setWindowModality(Qt.ApplicationModal)
        # 设置对话框样式
        self.setStyleSheet("""
            QDialog {
                background-color: #2c3e50;
            }
        """)
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(175, 175, 175, 90))
        shadow.setOffset(3, 3)
        self.setGraphicsEffect(shadow)
        # 生成验证码
        self.generate_captcha()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        # 标题
        title_label = QLabel("操作验证")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setStyleSheet("color: white;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        # 说明文字
        instruction_label = QLabel("请输入图片中的文字(不区分大小写)")
        instruction_label.setAlignment(Qt.AlignCenter)
        instruction_label.setStyleSheet("color: #bdc3c7; font-size: 12px;")
        layout.addWidget(instruction_label)
        # 验证码图片显示区域
        captcha_frame = QFrame()
        captcha_frame.setStyleSheet("""
            QFrame {
                background-color: transparent;
            }
        """)
        captcha_layout = QVBoxLayout(captcha_frame)
        self.captcha_label = QLabel()
        self.captcha_label.setAlignment(Qt.AlignCenter)
        self.update_captcha_image()
        captcha_layout.addWidget(self.captcha_label)
        layout.addWidget(captcha_frame)
        
        # 输入框容器，用于实现抖动效果
        input_container = QWidget()
        input_layout = QVBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        
        self.answer_input = QLineEdit()
        self.answer_input.setPlaceholderText("输入验证码")
        self.answer_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #3498db;
                border-radius: 8px;
                background-color: #34495e;
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #2980b9;
            }
            QLineEdit.error {
                border-color: #e74c3c;
                background-color: #492d2d;
            }
        """)
        
        # 创建错误消息标签
        self.error_label = QLabel()
        self.error_label.setStyleSheet("""
            QLabel {
                color: #e74c3c;
                font-size: 12px;
                padding: 2px 5px;
                background-color: transparent;
            }
        """)
        self.error_label.setVisible(False)
        
        input_layout.addWidget(self.answer_input)
        input_layout.addWidget(self.error_label)
        layout.addWidget(input_container)
        
        # 按钮布局
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        # 刷新按钮
        refresh_button = QPushButton("换一张")
        refresh_button.clicked.connect(self.refresh_captcha)
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        button_layout.addWidget(refresh_button)
        button_layout.addStretch()
        # 提交按钮
        submit_button = QPushButton("验证")
        submit_button.clicked.connect(self.verify_answer)
        submit_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(submit_button)
        layout.addLayout(button_layout)
        # 底部提示
        footer_label = QLabel("© DNE 2026 - 安全验证系统")
        footer_label.setAlignment(Qt.AlignCenter)
        footer_label.setStyleSheet("color: #7f8c8d; font-size: 10px; margin-top: 10px;")
        layout.addWidget(footer_label)
    
    def generate_captcha(self):
        """生成验证码文字"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        self.captcha_text = ''.join(random.choice(chars) for _ in range(6))
        self.captcha_display_text = ''.join(random.sample(self.captcha_text, len(self.captcha_text)))
    
    def create_gradient_background(self, width, height):
        """创建渐变背景"""
        image = Image.new('RGB', (width, height), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        
        direction = random.choice(['horizontal', 'vertical', 'diagonal'])
        color1 = (random.randint(220, 255), random.randint(220, 255), random.randint(220, 255))
        color2 = (random.randint(200, 230), random.randint(200, 230), random.randint(200, 230))
        
        if direction == 'horizontal':
            for x in range(width):
                r = int(color1[0] + (color2[0] - color1[0]) * x / width)
                g = int(color1[1] + (color2[1] - color1[1]) * x / width)
                b = int(color1[2] + (color2[2] - color1[2]) * x / width)
                draw.line([(x, 0), (x, height)], fill=(r, g, b))
        elif direction == 'vertical':
            for y in range(height):
                r = int(color1[0] + (color2[0] - color1[0]) * y / height)
                g = int(color1[1] + (color2[1] - color1[1]) * y / height)
                b = int(color1[2] + (color2[2] - color1[2]) * y / height)
                draw.line([(0, y), (width, y)], fill=(r, g, b))
        else:  # diagonal
            for x in range(width):
                for y in range(height):
                    ratio = (x + y) / (width + height)
                    r = int(color1[0] + (color2[0] - color1[0]) * ratio)
                    g = int(color1[1] + (color2[1] - color1[1]) * ratio)
                    b = int(color1[2] + (color2[2] - color1[2]) * ratio)
                    draw.point((x, y), fill=(r, g, b))
        
        return image
    
    def add_complex_background_noise(self, draw, width, height):
        """添加复杂的背景干扰"""
        # 添加密集的噪点
        for _ in range(1200):
            x, y = random.randint(0, width-1), random.randint(0, height-1)
            color = (random.randint(180, 255), random.randint(180, 255), random.randint(180, 255))
            draw.point((x, y), fill=color)
        
        # 添加曲线干扰线
        for _ in range(35):
            points = []
            for i in range(3):
                x = random.randint(0, width)
                y = random.randint(0, height)
                points.append((x, y))
            color = (random.randint(150, 220), random.randint(150, 220), random.randint(150, 220))
            draw.line(points, fill=color, width=random.randint(1, 3))
    
    def generate_captcha_image(self):
        """生成验证码图片"""
        width, height = 300, 120
        image = self.create_gradient_background(width, height)
        draw = ImageDraw.Draw(image)
        
        self.add_complex_background_noise(draw, width, height)
        
        # 尝试加载字体
        try:
            font = ImageFont.truetype("arial.ttf", 36)
        except:
            font = ImageFont.load_default()
        
        # 绘制字符
        total_width = len(self.captcha_display_text) * 35
        start_x = (width - total_width) // 2
        y = (height - 50) // 2
        
        for i, char in enumerate(self.captcha_display_text):
            x = start_x + i * 35 + random.randint(-5, 5)
            angle = random.randint(-20, 20)
            
            # 随机颜色
            r = random.randint(0, 100)
            g = random.randint(0, 100)
            b = random.randint(0, 100)
            color = (r, g, b)
            
            # 创建字符层
            char_img = Image.new('RGBA', (50, 60), (0, 0, 0, 0))
            char_draw = ImageDraw.Draw(char_img)
            char_draw.text((5, 5), char, font=font, fill=color)
            char_img = char_img.rotate(angle, expand=True, fillcolor=(0, 0, 0, 0))
            
            # 随机缩放
            scale = random.uniform(0.8, 1.2)
            new_width = int(char_img.width * scale)
            new_height = int(char_img.height * scale)
            if new_width > 0 and new_height > 0:
                char_img = char_img.resize((new_width, new_height))
            
            # 粘贴到主图像
            paste_x = x - char_img.width // 2 + 25
            paste_y = y - char_img.height // 2 + 30
            image.paste(char_img, (paste_x, paste_y), char_img)
        
        # 添加干扰线
        for _ in range(6):
            x1, y1 = random.randint(0, width), random.randint(0, height)
            x2, y2 = random.randint(0, width), random.randint(0, height)
            color = (random.randint(50, 150), random.randint(50, 150), random.randint(50, 150))
            draw.line([(x1, y1), (x2, y2)], fill=color, width=2)
        
        # 转换为QImage
        img_byte_arr = BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        qimage = QImage()
        qimage.loadFromData(img_byte_arr)
        return qimage
    
    def update_captcha_image(self):
        """更新验证码图片显示"""
        captcha_image = self.generate_captcha_image()
        pixmap = QPixmap.fromImage(captcha_image)
        self.captcha_label.setPixmap(pixmap)
    
    def shake_input(self):
        """抖动输入框效果"""
        # 清除之前的动画
        if hasattr(self, '_shake_animation'):
            self._shake_animation.stop()
        
        # 获取输入框的原始位置
        original_pos = self.answer_input.pos()
        
        # 创建抖动动画
        self._shake_animation = QPropertyAnimation(self.answer_input, b"pos")
        self._shake_animation.setDuration(400)  # 动画持续时间
        self._shake_animation.setEasingCurve(QEasingCurve.OutInBounce)
        
        # 设置关键帧
        key_values = [
            (0, original_pos),
            (0.1, QPoint(original_pos.x() - 8, original_pos.y())),  # 向左
            (0.2, QPoint(original_pos.x() + 8, original_pos.y())),  # 向右
            (0.3, QPoint(original_pos.x() - 6, original_pos.y())),  # 向左
            (0.4, QPoint(original_pos.x() + 6, original_pos.y())),  # 向右
            (0.5, QPoint(original_pos.x() - 4, original_pos.y())),  # 向左
            (0.6, QPoint(original_pos.x() + 4, original_pos.y())),  # 向右
            (0.7, QPoint(original_pos.x() - 2, original_pos.y())),  # 向左
            (0.8, QPoint(original_pos.x() + 2, original_pos.y())),  # 向右
            (1.0, original_pos)  # 回到原位
        ]
        
        for key, value in key_values:
            self._shake_animation.setKeyValueAt(key, value)
        
        # 设置错误样式
        self.answer_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #e74c3c;
                border-radius: 8px;
                background-color: #492d2d;
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #e74c3c;
            }
        """)
        
        # 显示错误消息
        self.error_label.setText("验证码错误，请重试！")
        self.error_label.setVisible(True)
        
        # 连接动画完成信号
        self._shake_animation.finished.connect(self.on_shake_finished)
        # QTimer.singleShot(1000, lambda: self._shake_animation.start())
        # 开始动画
        self._shake_animation.start()
    
    def on_shake_finished(self):
        """抖动动画完成后的回调"""
        # 恢复正常样式
        time.sleep(0.7)
        self.answer_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #3498db;
                border-radius: 8px;
                background-color: #34495e;
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #2980b9;
            }
        """)
        
        # 清空输入框并获取焦点
        self.answer_input.clear()
        self.answer_input.setFocus()
        # 隐藏错误消息
        self.error_label.setVisible(False)
        # 断开信号连接
        self._shake_animation.finished.disconnect(self.on_shake_finished)
        self.refresh_captcha()
    
    def verify_answer(self):
        """验证用户输入"""
        user_input = self.answer_input.text().strip()
        if not user_input:
            self.error_label.setText("请输入验证码！")
            self.error_label.setVisible(True)
            self.shake_input()
            return
        
        user_input_lower = user_input.lower()
        correct_answer_lower = self.captcha_text.lower()
        
        # 检查用户输入是否包含所有正确字符
        is_valid = True
        for char in correct_answer_lower:
            if char not in user_input_lower:
                is_valid = False
                break
        
        if is_valid:
            self.accept()  # 验证通过,关闭对话框
        else:
            self.shake_input()
    
    def refresh_captcha(self):
        """刷新验证码"""
        self.generate_captcha()
        self.update_captcha_image()
        self.answer_input.clear()
        self.answer_input.setFocus()
        
        # 隐藏错误消息
        self.error_label.setVisible(False)
        
        # 恢复输入框正常样式
        self.answer_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #3498db;
                border-radius: 8px;
                background-color: #34495e;
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #2980b9;
            }
        """)
    
    def keyPressEvent(self, event):
        """键盘事件处理"""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.verify_answer()
        else:
            super().keyPressEvent(event)


class EncryptPage(QWidget):
    """加密工具页面"""
    def __init__(self):
        super().__init__()
        self.file_path = ""
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("文本加密工具")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.back_btn = QPushButton("返回")
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        title_layout.addWidget(self.back_btn)
        
        layout.addWidget(title_frame)
        
        # 输入区域
        input_group = QGroupBox("要加密的文本")
        input_group.setGraphicsEffect(self.create_shadow())
        input_layout = QVBoxLayout(input_group)
        
        self.input_text = QTextEdit()
        self.input_text.setFont(QFont("宋体", 10))
        self.input_text.setMinimumHeight(150)
        self.input_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        input_layout.addWidget(self.input_text)
        
        layout.addWidget(input_group)
        
        # 文件保存区域
        file_group = QGroupBox("保存设置")
        file_group.setGraphicsEffect(self.create_shadow())
        file_layout = QVBoxLayout(file_group)
        
        # 文件路径选择
        path_layout = QHBoxLayout()
        self.path_label = QLabel("未选择保存位置")
        self.path_label.setStyleSheet("border: 1px solid #ccc; padding: 5px; background-color: #2c3e50;")
        self.path_label.setWordWrap(True)
        path_layout.addWidget(self.path_label)
        
        browse_btn = QPushButton("选择位置")
        browse_btn.clicked.connect(self.browse_save_location)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        path_layout.addWidget(browse_btn)
        file_layout.addLayout(path_layout)
        
        layout.addWidget(file_group)
        
        # 控制按钮区域
        control_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("加密并保存")
        encrypt_btn.clicked.connect(self.encrypt_text)
        encrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #ccc;
            }
        """)
        control_layout.addWidget(encrypt_btn)
        
        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self.clear_all)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        control_layout.addWidget(clear_btn)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # 解密区域（可选功能）
        decrypt_group = QGroupBox("解密工具（读取文件）")
        decrypt_group.setGraphicsEffect(self.create_shadow())
        decrypt_layout = QVBoxLayout(decrypt_group)
        
        # 解密文件选择
        decrypt_file_layout = QHBoxLayout()
        self.decrypt_path_label = QLabel("未选择解密文件")
        self.decrypt_path_label.setStyleSheet("border: 1px solid #ccc; padding: 5px; background-color: #2c3e50;")
        self.decrypt_path_label.setWordWrap(True)
        decrypt_file_layout.addWidget(self.decrypt_path_label)
        
        decrypt_browse_btn = QPushButton("选择文件")
        decrypt_browse_btn.clicked.connect(self.browse_decrypt_file)
        decrypt_browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        decrypt_file_layout.addWidget(decrypt_browse_btn)
        decrypt_layout.addLayout(decrypt_file_layout)
        
        # 解密按钮
        decrypt_btn = QPushButton("解密文件")
        decrypt_btn.clicked.connect(self.decrypt_file)
        decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        decrypt_layout.addWidget(decrypt_btn)
        
        # 解密结果显示
        self.decrypt_result = QTextEdit()
        self.decrypt_result.setFont(QFont("宋体", 10))
        self.decrypt_result.setMaximumHeight(100)
        self.decrypt_result.setReadOnly(True)
        self.decrypt_result.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: #2c3e50;
            }
        """)
        decrypt_layout.addWidget(self.decrypt_result)
        
        layout.addWidget(decrypt_group)
        
        # 状态栏
        self.status_label = QLabel("准备就绪")
        self.status_label.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        self.status_label.setStyleSheet("""
            QLabel {
                padding: 3px;
                background-color: #2c3e50;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
    
    def create_shadow(self):
        """创建阴影效果"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)
        return shadow
    
    def browse_save_location(self):
        """选择保存位置"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存加密文件", 
            f"加密文件_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin",
            "加密文件 (*.bin);;所有文件 (*.*)"
        )
        
        if file_path:
            self.file_path = file_path
            self.path_label.setText(file_path)
            self.status_label.setText(f"已选择保存位置: {os.path.basename(file_path)}")
    
    def browse_decrypt_file(self):
        """选择解密文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择加密文件", "", "加密文件 (*.bin);;所有文件 (*.*)"
        )
        
        if file_path:
            self.decrypt_file_path = file_path
            self.decrypt_path_label.setText(file_path)
            self.decrypt_result.clear()
            self.status_label.setText(f"已选择解密文件: {os.path.basename(file_path)}")
    
    def encrypt_text(self):
        """加密文本并保存"""
        text = self.input_text.toPlainText().strip()
        
        if not text:
            self.status_label.setText("请输入要加密的文本")
            messageboxall("提示", "请输入要加密的文本", "w")
            return
        
        if not self.file_path:
            self.status_label.setText("请选择保存位置")
            messageboxall("提示", "请选择保存位置", "w")
            return
        
        try:
            # 调用加密函数
            result = bin_crypto.binapi_enc(text, self.file_path)
            
            # 显示结果
            self.status_label.setText("加密成功")
            self.decrypt_result.clear()
            self.decrypt_result.setPlainText(f"加密结果:\n{result}")
            
            # 清空输入
            self.input_text.clear()
            self.file_path = ""
            self.path_label.setText("未选择保存位置")
            
            messageboxall("成功", "文本已加密并保存", "i")
            
        except Exception as e:
            error_msg = f"加密失败: {str(e)}"
            self.status_label.setText(error_msg)
            log_event(f"加密失败: {str(e)}", level="ERROR")
            messageboxall("错误", error_msg, "e")
    
    def decrypt_file(self):
        """解密文件"""
        if not hasattr(self, 'decrypt_file_path') or not self.decrypt_file_path:
            self.status_label.setText("请选择要解密的文件")
            messageboxall("提示", "请选择要解密的文件", "w")
            return
        
        if not os.path.exists(self.decrypt_file_path):
            self.status_label.setText("文件不存在")
            messageboxall("错误", "文件不存在", "e")
            return
        
        try:
            # 调用解密函数
            result = bin_crypto.binapi_dec(self.decrypt_file_path)
            
            # 显示解密结果
            self.status_label.setText("解密成功")
            self.decrypt_result.clear()
            self.decrypt_result.setPlainText(result)
            
            # 解密成功后将结果复制到输入框中以便查看
            if result.startswith("✅ 解密成功"):
                # 提取实际的文本内容
                lines = result.split('\n', 1)
                if len(lines) > 1:
                    self.input_text.setPlainText(lines[1])
            
        except Exception as e:
            error_msg = f"解密失败: {str(e)}"
            self.status_label.setText(error_msg)
            self.decrypt_result.setPlainText(error_msg)
            log_event(f"解密失败: {str(e)}", level="ERROR")
    
    def clear_all(self):
        """清空所有内容"""
        self.input_text.clear()
        self.decrypt_result.clear()
        self.file_path = ""
        self.path_label.setText("未选择保存位置")
        if hasattr(self, 'decrypt_file_path'):
            delattr(self, 'decrypt_file_path')
        self.decrypt_path_label.setText("未选择解密文件")
        self.status_label.setText("已清空")

class LoginDialog(QDialog):
    """登录/注册对话框"""
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.pcount = 0  # 密码错误计数器
        self.maxc= 2  # 最大错误次数后需要验证码
        self.setWindowTitle("用户登录")
        self.setFixedSize(350, 400)
        self.setWindowModality(Qt.ApplicationModal)
        # 设置对话框样式
        self.setStyleSheet("""
            QDialog {
                background-color: #2c3e50;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #3498db;
                border-radius: 6px;
                background-color: #34495e;
                color: white;
            }
            QLineEdit:focus {
                border-color: #2980b9;
            }
            QLabel {
                color: white;
                font-size: 13px;
            }
        """)
        
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 150))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # 标题
        title_label = QLabel("用户登录/注册")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setStyleSheet("color: white;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # 输入区域
        input_layout = QVBoxLayout()
        input_layout.setSpacing(15)
        
        # 用户名输入
        username_label = QLabel("用户名:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("请输入用户名")
        input_layout.addWidget(username_label)
        input_layout.addWidget(self.username_input)
        
        # 密码输入
        password_label = QLabel("密码:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("请输入密码")
        self.password_input.setEchoMode(QLineEdit.Password)
        input_layout.addWidget(password_label)
        input_layout.addWidget(self.password_input)
        
        layout.addLayout(input_layout)
        layout.addSpacing(20)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        login_btn = QPushButton("登录")
        login_btn.clicked.connect(self.login)
        login_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        button_layout.addWidget(login_btn)
        
        register_btn = QPushButton("注册")
        register_btn.clicked.connect(self.register)
        register_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        button_layout.addWidget(register_btn)
        
        layout.addLayout(button_layout)
        
        # 状态标签
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #ff9800; font-size: 12px;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # 底部提示
        footer_label = QLabel("© DNE 2026 - 用户系统")
        footer_label.setAlignment(Qt.AlignCenter)
        footer_label.setStyleSheet("color: #7f8c8d; font-size: 10px; margin-top: 10px;")
        layout.addWidget(footer_label)
    # 有没有一种可能,一个用户把自己的密码哈希值和盐覆盖到其他用户的json中就能破解呢
    def login(self):
        """用户登录"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            self.status_label.setText("用户名和密码不能为空")
            return
        # 如果密码错误次数达到2次,需要重新进行人机验证
        if self.pcount >= self.maxc:
            self.status_label.setText("密码错误次数过多,请重新进行人机验证")
            # 通知父窗口需要重新验证
            self.reject()  # 关闭登录对话框
            # 发送信号通知需要重新验证(通过返回值)
            return
        success, message = self.user_manager.login(username, password)
        if success:
            # 登录成功,重置错误计数器
            self.pcount = 0
            self.accept()
        else:
            # 登录失败,增加错误计数器
            self.pcount += 1
            error_message = message
            if self.pcount >= self.maxc:
                error_message += f"(错误{self.pcount}次,需要重新验证)"
            else:
                error_message += f"(错误{self.pcount}次)"
            self.status_label.setText(error_message)
            # 如果达到最大错误次数,提示需要重新验证
            if self.pcount >= self.maxc:
                QTimer.singleShot(2000, lambda: self.status_label.setText("请关闭此窗口重新验证"))
    
    def register(self):
        """用户注册"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            self.status_label.setText("用户名和密码不能为空")
            return
        # if len(username) < 2:
            # self.status_label.setText("用户名至少2个字符")
            # return
        if len(password) < 6:
            self.status_label.setText("密码至少6个字符")
            return
        messageboxall("安全增强","请随机移动鼠标以生成加密随机数\n\n鼠标移动轨迹将用于增强密码安全性\n请持续移动鼠标直到进度条完成","i")
        # 显示随机数生成对话框
        self.status_label.setText("正在生成安全随机数...")
        self.status_label.setStyleSheet("color: #3498db; font-size: 12px;")
        # time.sleep(2)
        # 更新UI以显示状态
        QApplication.processEvents()
        # 创建并显示随机数生成对话框
        random_dialog = MouseRandomDialog(self)
        # 将登录对话框设置为不可用但保持显示
        self.setEnabled(False)
        if random_dialog.exec() == QDialog.Accepted:
            # 获取生成的随机数据
            mouse_random = random_dialog.get_random_data()
            if mouse_random:
                # 恢复登录对话框
                self.setEnabled(True)
                # 使用鼠标随机数进行注册
                success, message = self.user_manager.register(username, password, mouse_random)
                self.status_label.setText(message)
                if success:
                    # 注册成功后自动登录
                    success, message = self.user_manager.login(username, password)
                    if success:
                        self.password_error_count = 0
                        self.accept()
                    else:
                        self.status_label.setText(f"注册成功但自动登录失败: {message}")
                else:
                    self.status_label.setText(message)
            else:
                # 随机数生成失败
                self.setEnabled(True)
                self.status_label.setText("随机数生成失败, 请重试注册")
                self.status_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        else:
            # 用户取消了随机数生成
            self.setEnabled(True)
            self.status_label.setText("注册已取消")
            self.status_label.setStyleSheet("color: #f39c12; font-size: 12px;")

class MouseRandomDialog(QDialog):
    """鼠标移动随机数生成对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("安全性增强 - 随机数生成")
        self.setFixedSize(500, 300)
        self.setWindowModality(Qt.ApplicationModal)
        self.installEventFilter(self)
        # 初始化鼠标数据收集
        self.mouse_positions = []
        self.timestamps = []
        self.collecting = True
        self.collection_time = 5  # 收集5秒
        self.elapsed_time = 0
        
        # 设置对话框样式
        self.setStyleSheet("""
            QDialog {
                background-color: #2c3e50;
                border-radius: 15px;
            }
            QLabel {
                color: white;
            }
        """)
        
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 150))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)
        self.init_ui()
        self.start_collection()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        self.setMouseTracking(True)
        # 标题
        title_label = QLabel("安全性增强 - 随机数生成")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        # 说明文字
        instruction_label = QLabel(
            "请随机移动鼠标以生成加密随机数\n\n"
            "鼠标移动轨迹将用于增强密码安全性\n"
            "请持续移动鼠标直到进度条完成"
        )
        instruction_label.setAlignment(Qt.AlignCenter)
        instruction_label.setWordWrap(True)
        instruction_label.setStyleSheet("color: #bdc3c7; font-size: 13px;")
        layout.addWidget(instruction_label)
        # 统计数据
        stats_layout = QHBoxLayout()
        self.points_label = QLabel("采集点数: 0")
        self.points_label.setStyleSheet("color: #3498db; font-weight: bold;")
        stats_layout.addWidget(self.points_label)
        self.entropy_label = QLabel("熵值: 0.0 bits")
        self.entropy_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        stats_layout.addWidget(self.entropy_label)
        self.time_label = QLabel("剩余时间: 5.0秒")
        self.time_label.setStyleSheet("color: #2ecc71; font-weight: bold;")
        stats_layout.addWidget(self.time_label)
        layout.addLayout(stats_layout)
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #34495e;
                border-radius: 8px;
                text-align: center;
                background-color: #2c3e50;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # 状态标签
        self.status_label = QLabel("开始移动鼠标...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f39c12; font-weight: bold;")
        layout.addWidget(self.status_label)
        # # 按钮区域
        # button_layout = QHBoxLayout()
        # button_layout.addStretch()
        # okbtn = QPushButton("开始")
        # okbtn.clicked.connect(self.start_collection)
        # okbtn.setStyleSheet("""
        #     QPushButton {
        #         background-color: #4CAF50;
        #         color: white;
        #         border: none;
        #         padding: 12px 30px;
        #         border-radius: 8px;
        #         font-weight: bold;
        #         font-size: 14px;
        #     }
        #     QPushButton:hover {
        #         background-color: #45a049;
        #     }
        # """)
        # button_layout.addWidget(okbtn)
        # cancel_btn = QPushButton("取消")
        # cancel_btn.clicked.connect(self.reject)
        # cancel_btn.setStyleSheet("""
        #     QPushButton {
        #         background-color: #e74c3c;
        #         color: white;
        #         border: none;
        #         padding: 8px 20px;
        #         border-radius: 6px;
        #         font-weight: bold;
        #     }
        #     QPushButton:hover {
        #         background-color: #c0392b;
        #     }
        # """)
        # button_layout.addWidget(cancel_btn)
        # layout.addLayout(button_layout)
        # 底部提示
        footer_label = QLabel("© DNE 2026 - 安全增强系统")
        footer_label.setAlignment(Qt.AlignCenter)
        footer_label.setStyleSheet("color: #7f8c8d; font-size: 10px; margin-top: 10px;")
        layout.addWidget(footer_label)
    
    def eventFilter(self, obj, event):
        if event.type() == QEvent.MouseMove and self.collecting:
            # 处理鼠标移动
            self.mouseMoveEvent(event)
            # 不拦截事件让事件继续传递
            return False
        return super().eventFilter(obj, event)
    
    def start_collection(self):
        """开始收集鼠标数据"""
        self.collection_timer = QTimer()
        self.collection_timer.timeout.connect(self.update_collection)
        self.collection_timer.start(100)  # 每100毫秒更新一次
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(100)  # 每100毫秒更新进度条
    
    def update_collection(self):
        """更新收集状态"""
        if not self.collecting:
            return
        self.elapsed_time += 0.1
        # 更新显示
        remaining = max(0, self.collection_time - self.elapsed_time)
        self.time_label.setText(f"剩余时间: {remaining:.1f}秒")
        # 计算熵值
        entropy = self.calculate_entropy()
        self.entropy_label.setText(f"熵值: {entropy:.2f} bits")
        # 检查是否完成
        if self.elapsed_time >= self.collection_time:
            self.finish_collection()
    
    def update_progress(self):
        """更新进度条"""
        if not self.collecting:
            return
        progress = min(100, int((self.elapsed_time / self.collection_time) * 100))
        self.progress_bar.setValue(progress)
        # 根据进度更新状态标签
        if progress < 15:
            self.status_label.setText("很像微软的提示标签: 请移动鼠标...")
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        elif progress < 30:
            self.status_label.setText("继续移动鼠标...")
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        elif progress < 70:
            self.status_label.setText("很好, 继续移动...")
            self.status_label.setStyleSheet("color: #f39c12; font-weight: bold;")
        else:
            self.status_label.setText("即将完成...")
            self.status_label.setStyleSheet("color: #2ecc71; font-weight: bold;")
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """鼠标移动事件"""
        if not self.collecting:
            return
        # 记录鼠标位置和时间戳
        pos = event.position().toPoint()
        timestamp = time.time()
        self.mouse_positions.append((pos.x(), pos.y()))
        self.timestamps.append(timestamp)
        # 更新点数显示
        self.points_label.setText(f"采集点数: {len(self.mouse_positions)}")
        # 更新状态提示
        if len(self.mouse_positions) % 10 == 0:
            self.status_label.setText(f"已采集 {len(self.mouse_positions)} 个点...")
    
    def calculate_entropy(self):
        """计算熵值"""
        if len(self.mouse_positions) < 2:
            return 0.0
        
        # 计算鼠标位置的变化
        diffs = []
        for i in range(1, len(self.mouse_positions)):
            x1, y1 = self.mouse_positions[i-1]
            x2, y2 = self.mouse_positions[i]
            diff = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
            diffs.append(diff)
        if not diffs:
            return 0.0
        # 简单熵值估算
        avg_diff = sum(diffs) / len(diffs)
        if avg_diff == 0:
            return 0.0
        # 基于变化程度和点数估算熵值
        entropy = min(128.0, math.log2(len(self.mouse_positions) * avg_diff + 1) * 2)
        return entropy
    
    def finish_collection(self):
        """完成收集"""
        self.collecting = False
        self.collection_timer.stop()
        self.progress_timer.stop()
        # 生成随机数
        random_data = self.generate_random_data()
        if random_data:
            self.generated_random = random_data
            self.status_label.setText("✓ 随机数生成成功")
            self.status_label.setStyleSheet("color: #2ecc71; font-weight: bold;")
            # 延迟1秒后自动关闭
            QTimer.singleShot(1000, self.accept)
        else:
            self.status_label.setText("✗ 随机数生成失败，请重试")
            self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
    
    # def generate_random_data(self):
    #     """根据鼠标轨迹生成随机数"""
    #     try:
    #         if len(self.mouse_positions) < 10:
    #             return None
    #         # 将鼠标位置和时间戳组合成随机数据
    #         data = b""
    #         for i, (x, y) in enumerate(self.mouse_positions):
    #             timestamp = self.timestamps[i]
    #             # 将数据转换为字节
    #             data += struct.pack("IIQ", x, y, int(timestamp * 1000000))
    #         # 使用SHA-512生成256位的随机数据
    #         random_hash = sha512(data).digest()[:32]  # 取前32字节(256位)
    #         # 转换为十六进制字符串
    #         random_hex = binascii.hexlify(random_hash).decode('utf-8')
    #         log_event(f"生成随机数: {len(self.mouse_positions)}个点, 熵值: {self.calculate_entropy():.2f} bits", level="INFO")
    #         return random_hex
    #     except struct.error as n:
    #         log_event(f"错误: {n}\n如果错误为'argument out of range',请移动鼠标慢一点,因为这可能是因为随机数过大导致超出64位整数限制,目前无法修复")
    #     except Exception as eee:
    #         log_event(f"错误:{eee}","ERROR")
    #         return secrets.token_hex(16)
    
    def generate_random_data(self):
        """根据鼠标轨迹生成随机数"""
        try:
            if len(self.mouse_positions) < 10:
                return None
            # 将鼠标位置和时间戳组合成随机数据
            data = b""
            baseline_time = self.timestamps[0] if self.timestamps else 0
            for i, (x, y) in enumerate(self.mouse_positions):
                timestamp = self.timestamps[i]
                # 使用相对时间毫秒差
                time_diff = int((timestamp - baseline_time) * 1000)
                # 转换为字节避免 struct 的限制
                # 使用4字节整数
                x_bytes = x.to_bytes(4, 'little', signed=True)
                y_bytes = y.to_bytes(4, 'little', signed=True)
                time_bytes = time_diff.to_bytes(4, 'little', signed=False)
                data += x_bytes + y_bytes + time_bytes
            # 使用SHA-512生成256位的随机数据
            random_hash = sha512(data).digest()[:32]
            # 转换为十六进制字符串
            random_hex = binascii.hexlify(random_hash).decode('utf-8')
            log_event(f"生成随机数: {len(self.mouse_positions)}个点, 熵值: {self.calculate_entropy():.2f} bits", level="INFO")
            return random_hex
        except Exception as eee:
            log_event(f"错误:{eee}","ERROR")
            return secrets.token_hex(16)
    
    def get_random_data(self):
        """获取生成的随机数据"""
        return getattr(self, 'generated_random', None)

class HistoryWindow(QDialog):
    """历史记录对话框"""
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.setWindowTitle(f"{self.user_manager.current_user} - 历史记录")
        self.setModal(True)  # 设置为模态对话框
        self.setFixedSize(900, 600)  # 设置固定大小
        # 设置对话框样式
        self.setStyleSheet("""
            QDialog {
                background-color: #2c3e50;
            }
        """)
        
        # 添加阴影效果
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 150))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)
        
        self.init_ui()
        self.load_history()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)
        # 标题栏
        title_layout = QHBoxLayout()
        title_label = QLabel(f"用户: {self.user_manager.current_user} - 识别历史")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: white;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        # 关闭按钮
        # close_btn = QPushButton("✕")
        # close_btn.setFixedSize(30, 30)
        # close_btn.setStyleSheet("""
            # QPushButton {
                # background-color: transparent;
                # color: white;
                # border: none;
                # font-size: 16px;
                # font-weight: bold;
                # border-radius: 6px;
            # }
            # QPushButton:hover {
                # background-color: #e74c3c;
            # }
        # """)
        # close_btn.clicked.connect(self.close)
        # title_layout.addWidget(close_btn)
        layout.addLayout(title_layout)
        
        # 历史记录表格
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["时间", "图片路径", "识别文本", "用时(秒)"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # 设置表格样式
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #34495e;
                alternate-background-color: #2c3e50;
                color: white;
                gridline-color: #4a5f7a;
                border: 1px solid #4a5f7a;
            }
            QHeaderView::section {
                background-color: #1f2c39;
                color: white;
                padding: 8px;
                border: 1px solid #4a5f7a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #4a5f7a;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        
        layout.addWidget(self.table)
        
        # 操作按钮
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        view_btn = QPushButton("查看详情")
        view_btn.clicked.connect(self.view_details)
        view_btn.setFixedSize(100, 35)
        view_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:disabled {
                background-color: #666;
                color: #999;
            }
        """)
        button_layout.addWidget(view_btn)
        
        export_btn = QPushButton("导出选中")
        export_btn.clicked.connect(self.export_selected)
        export_btn.setFixedSize(100, 35)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666;
                color: #999;
            }
        """)
        button_layout.addWidget(export_btn)
        
        clear_btn = QPushButton("清空历史")
        clear_btn.clicked.connect(self.clear_history)
        clear_btn.setFixedSize(100, 35)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        button_layout.addWidget(clear_btn)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.load_history)
        refresh_btn.setFixedSize(80, 35)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 状态标签
        self.status_label = QLabel("双击表格行查看详细信息,选中行后可导出")
        self.status_label.setStyleSheet("color: #7f8c8d; font-size: 12px; padding-top: 5px;")
        layout.addWidget(self.status_label)
        # 连接表格双击事件
        self.table.doubleClicked.connect(self.view_details)
        # 连接表格选择变化事件
        self.table.itemSelectionChanged.connect(self.update_button_state)
        # 初始化按钮状态
        self.update_button_state()
    
    def update_button_state(self):
        """根据表格选择状态更新按钮"""
        has_selection = self.table.currentRow() >= 0
        for i in range(self.layout().count()):
            widget = self.layout().itemAt(i).widget()
            if isinstance(widget, QPushButton) and widget.text() in ["查看详情", "导出选中"]:
                widget.setEnabled(has_selection)
    
    def load_history(self):
        """加载历史记录"""
        history = self.user_manager.get_history()
        self.table.setRowCount(len(history))
        
        for row, record in enumerate(history):
            # 时间列
            time_item = QTableWidgetItem(record["timestamp"])
            time_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, time_item)
            
            # 图片路径列
            path_item = QTableWidgetItem(record["image_path"])
            path_item.setToolTip(record["image_path"])  # 添加工具提示显示完整路径
            self.table.setItem(row, 1, path_item)
            
            # 识别文本列
            text_preview = record["text"][:50] + "..." if len(record["text"]) > 50 else record["text"]
            text_item = QTableWidgetItem(text_preview)
            text_item.setToolTip(record["text"])  # 添加工具提示显示完整文本
            self.table.setItem(row, 2, text_item)
            
            # 用时列
            time_taken_item = QTableWidgetItem(record["time_taken"])
            time_taken_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, time_taken_item)
        
        # 调整列宽
        self.table.setColumnWidth(0, 150)  # 时间列
        self.table.setColumnWidth(1, 250)  # 路径列
        self.table.setColumnWidth(3, 80)   # 用时列
        self.status_label.setText(f"共找到 {len(history)} 条历史记录")
    
    def view_details(self):
        """查看详细信息"""
        selected = self.table.currentRow()
        if selected >= 0:
            history = self.user_manager.get_history()
            if selected < len(history):
                record = history[selected]
                
                # 创建详细信息对话框
                detail_dialog = QDialog(self)
                detail_dialog.setWindowTitle("识别详情")
                detail_dialog.setModal(True)
                detail_dialog.setFixedSize(700, 500)
                detail_dialog.setStyleSheet("""
                    QDialog {
                        background-color: #2c3e50;
                        border-radius: 15px;
                    }
                """)
                
                layout = QVBoxLayout(detail_dialog)
                layout.setSpacing(15)
                layout.setContentsMargins(20, 20, 20, 20)
                
                # 标题
                title_label = QLabel("识别详情")
                title_label.setFont(QFont("Arial", 16, QFont.Bold))
                title_label.setStyleSheet("color: white;")
                title_label.setAlignment(Qt.AlignCenter)
                layout.addWidget(title_label)
                
                # 基本信息
                info_group = QGroupBox("基本信息")
                info_group.setStyleSheet("""
                    QGroupBox {
                        color: white;
                        border: 2px solid #4a5f7a;
                        border-radius: 8px;
                        margin-top: 10px;
                        padding-top: 10px;
                    }
                    QGroupBox::title {
                        subcontrol-origin: margin;
                        left: 10px;
                        padding: 0 5px 0 5px;
                    }
                """)
                
                info_layout = QVBoxLayout(info_group)
                
                info_text = QLabel()
                info_text.setStyleSheet("color: #bdc3c7; font-size: 13px;")
                info_text.setTextFormat(Qt.RichText)
                info_text.setText(
                    f"<b>时间：</b>{record['timestamp']}<br>"
                    f"<b>图片路径：</b>{record['image_path']}<br>"
                    f"<b>识别用时：</b>{record['time_taken']}秒"
                )
                info_layout.addWidget(info_text)
                layout.addWidget(info_group)
                
                # 识别文本
                text_group = QGroupBox("识别结果")
                text_group.setStyleSheet("""
                    QGroupBox {
                        color: white;
                        border: 2px solid #4a5f7a;
                        border-radius: 8px;
                        margin-top: 10px;
                        padding-top: 10px;
                    }
                    QGroupBox::title {
                        subcontrol-origin: margin;
                        left: 10px;
                        padding: 0 5px 0 5px;
                    }
                """)
                
                text_layout = QVBoxLayout(text_group)
                text_edit = QTextEdit()
                text_edit.setPlainText(record["text"])
                text_edit.setReadOnly(True)
                text_edit.setFont(QFont("宋体", 10))
                text_edit.setStyleSheet("""
                    QTextEdit {
                        background-color: #34495e;
                        color: white;
                        border: 1px solid #4a5f7a;
                        border-radius: 6px;
                        padding: 10px;
                    }
                """)
                text_layout.addWidget(text_edit)
                layout.addWidget(text_group)
                # 按钮
                button_layout = QHBoxLayout()
                button_layout.addStretch()
                copy_btn = QPushButton("复制文本")
                copy_btn.clicked.connect(lambda: self.copy_text(record["text"]))
                copy_btn.setFixedSize(100, 35)
                copy_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #2196F3;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #1976D2;
                    }
                """)
                button_layout.addWidget(copy_btn)
                
                close_btn = QPushButton("关闭")
                close_btn.clicked.connect(detail_dialog.accept)
                close_btn.setFixedSize(100, 35)
                close_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #7f8c8d;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #666;
                    }
                """)
                button_layout.addWidget(close_btn)
                
                layout.addLayout(button_layout)
                
                detail_dialog.exec()
    
    def copy_text(self, text):
        """复制文本到剪贴板"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        
        # 显示复制成功提示
        self.show_status_message("文本已复制到剪贴板", success=True)
    
    def show_status_message(self, message, success=True):
        """显示状态消息"""
        self.status_label.setText(message)
        if success:
            self.status_label.setStyleSheet("color: #4CAF50; font-size: 12px; padding-top: 5px;")
        else:
            self.status_label.setStyleSheet("color: #f44336; font-size: 12px; padding-top: 5px;")
        # 3秒后恢复原状态
        QTimer.singleShot(3000, lambda: self.status_label.setText("双击表格行查看详细信息,选中行后可导出"))
        QTimer.singleShot(3000, lambda: self.status_label.setStyleSheet("color: #7f8c8d; font-size: 12px; padding-top: 5px;"))
    
    def export_selected(self):
        """导出选中的记录"""
        selected = self.table.currentRow()
        if selected >= 0:
            history = self.user_manager.get_history()
            if selected < len(history):
                record = history[selected]
                
                file_path, _ = QFileDialog.getSaveFileName(
                    self, "导出记录", 
                    f"OCR历史记录_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    "文本文件 (*.txt)"
                )
                
                if file_path:
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(f"=== OCR识别记录 ===\n")
                            f.write(f"时间: {record['timestamp']}\n")
                            f.write(f"图片路径: {record['image_path']}\n")
                            f.write(f"识别用时: {record['time_taken']}秒\n")
                            f.write(f"\n识别结果:\n")
                            f.write(f"{record['text']}\n")
                        
                        self.show_status_message(f"记录已导出到: {file_path}", success=True)
                        
                    except Exception as e:
                        self.show_status_message(f"导出失败: {str(e)}", success=False)
                        log_event(f"导出历史记录失败: {str(e)}", level="ERROR")
    
    def clear_history(self):
        """清空历史记录"""
        reply = messageboxall("确认清空", "确定要清空所有历史记录吗？此操作不可恢复！", "c")
        if reply:
            users = self.user_manager.load_users()
            if self.user_manager.current_user in users:
                users[self.user_manager.current_user]["history"] = []
                self.user_manager.save_users(users)
                self.table.setRowCount(0)
                self.show_status_message("历史记录已清空", success=True)
                messageboxall("成功", "历史记录已清空", "i")

class AdvancedSettingsPage(QWidget):
    """高级设置页面"""
    def __init__(self):
        super().__init__()
        self.settings = QSettings()
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # 标题栏
        title_frame = QFrame()
        title_frame.setFrameStyle(QFrame.StyledPanel)
        title_frame.setGraphicsEffect(self.create_shadow())
        title_layout = QHBoxLayout(title_frame)
        title_label = QLabel("高级设置")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        self.back_btn = QPushButton("返回")
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        title_layout.addWidget(self.back_btn)
        
        layout.addWidget(title_frame)
        
        # 高级设置内容区域
        advanced_group = QGroupBox("高级选项")
        advanced_group.setGraphicsEffect(self.create_shadow())
        advanced_layout = QVBoxLayout(advanced_group)
        
        # 自动检查更新设置
        auto_update_group = QGroupBox("更新设置")
        auto_update_layout = QVBoxLayout(auto_update_group)
        
        self.auto_update_check = QCheckBox("启动时自动检查更新")
        auto_update_layout.addWidget(self.auto_update_check)
        
        advanced_layout.addWidget(auto_update_group)
        
        # 日志级别设置
        log_level_group = QGroupBox("日志级别")
        log_level_layout = QHBoxLayout(log_level_group)
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        log_level_layout.addWidget(QLabel("日志级别:"))
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()
        
        advanced_layout.addWidget(log_level_group)
        
        # OCR线程数设置
        thread_group = QGroupBox("OCR线程设置")
        thread_layout = QHBoxLayout(thread_group)
        
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 8)
        thread_layout.addWidget(QLabel("CPU线程数:"))
        thread_layout.addWidget(self.thread_spin)
        thread_layout.addStretch()
        
        advanced_layout.addWidget(thread_group)
        
        # 自动保存设置
        auto_save_group = QGroupBox("自动保存")
        auto_save_layout = QVBoxLayout(auto_save_group)
        
        self.auto_save_check = QCheckBox("启用自动保存")
        auto_save_layout.addWidget(self.auto_save_check)
        
        save_path_layout = QHBoxLayout()
        self.save_path_edit = QLineEdit()
        self.save_path_edit.setPlaceholderText("保存路径...")
        self.save_path_edit.setReadOnly(True)
        save_path_layout.addWidget(self.save_path_edit)
        
        browse_save_btn = QPushButton("浏览")
        browse_save_btn.setStyleSheet("""
            QPushButton {
                background-color: #479D3C;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 7px;
            }
            QPushButton:hover {
                background-color: #36672F;
            }
        """)
        browse_save_btn.clicked.connect(self.browse_save_path)
        save_path_layout.addWidget(browse_save_btn)
        
        auto_save_layout.addLayout(save_path_layout)
        
        advanced_layout.addWidget(auto_save_group)
        
        zip_group = QGroupBox("zip破解  !实验性! 暂时不开放,没有做好")
        zip_layout = QVBoxLayout(zip_group)
        self.zip_edit = QLineEdit()
        self.zip_edit.setPlaceholderText("请输入zip路径,按回车键提交")
        self.zip_edit.setClearButtonEnabled(True)
        self.zip_edit.returnPressed.connect(self.zpcr)
        zip_layout.addWidget(self.zip_edit)
        self.zip_status_label = QLabel("")
        self.zip_status_label.setStyleSheet("color: #888; font-size: 12px;")
        zip_layout.addWidget(self.zip_status_label)
        
        # 重置按钮
        reset_btn = QPushButton("重置所有设置")
        reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        reset_btn.clicked.connect(self.reset_settings)
        advanced_layout.addWidget(reset_btn)
        
        # 保存设置按钮(可选)
        save_btn = QPushButton("立即保存设置")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        save_btn.clicked.connect(self.save_settings)
        advanced_layout.addWidget(save_btn)
        advanced_layout.addStretch()
        layout.addWidget(advanced_group)
        layout.addWidget(zip_group)
        self.auto_update_check.stateChanged.connect(self.save_settings)
        self.log_level_combo.currentTextChanged.connect(self.save_settings)
        self.thread_spin.valueChanged.connect(self.save_settings)
        self.auto_save_check.stateChanged.connect(self.save_settings)
        self.save_path_edit.textChanged.connect(self.save_settings)
        # 设置状态标签
        # self.settings_status_label = QLabel("设置已自动保存")
        # self.settings_status_label.setStyleSheet("color: #4CAF50; font-size: 12px;")
        # self.settings_status_label.hide()  # 默认隐藏
        # layout.addWidget(self.settings_status_label)
        
        # 警告提示
        warning_label = QLabel("⚠️ 警告：修改这些设置可能会影响程序的稳定性和性能！")
        warning_label.setStyleSheet("color: #ff9800; font-weight: bold; padding: 6px; background-color: #2c3e50; border-radius: 5px;")
        warning_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(warning_label)
        
        layout.addStretch()
    def load_settings(self):
        """加载保存的设置"""
        try:
            # 自动检查更新设置默认值为True
            auto_update = self.settings.value("auto_update", True, type=bool)
            self.auto_update_check.setChecked(auto_update)
            
            # 日志级别设置
            log_level = self.settings.value("log_level", "INFO", type=str)
            index = self.log_level_combo.findText(log_level)
            if index >= 0:
                self.log_level_combo.setCurrentIndex(index)
            
            # OCR线程数设置
            thread_count = self.settings.value("thread_count", 2, type=int)
            self.thread_spin.setValue(thread_count)
            
            # 自动保存设置
            auto_save = self.settings.value("auto_save", False, type=bool)
            self.auto_save_check.setChecked(auto_save)
            
            # 保存路径设置
            save_path = self.settings.value("save_path", "", type=str)
            self.save_path_edit.setText(save_path)
            
            log_event("loadsettingsSuccess", level="INFO")
            
        except Exception as e:
            log_event(f"加载设置失败: {str(e)}", level="ERROR")
            # 加载失败时使用默认值
            self.auto_update_check.setChecked(True)
            self.log_level_combo.setCurrentText("INFO")
            self.thread_spin.setValue(2)
            self.auto_save_check.setChecked(False)
            self.save_path_edit.clear()
    
    def save_settings(self):
        """保存当前设置"""
        try:
            # 保存自动检查更新设置
            self.settings.setValue("auto_update", self.auto_update_check.isChecked())
            
            # 保存日志级别设置
            self.settings.setValue("log_level", self.log_level_combo.currentText())
            
            # 保存OCR线程数设置
            self.settings.setValue("thread_count", self.thread_spin.value())
            
            # 保存自动保存设置
            self.settings.setValue("auto_save", self.auto_save_check.isChecked())
            
            # 保存保存路径设置
            self.settings.setValue("save_path", self.save_path_edit.text())
            
            # 同步设置到磁盘
            self.settings.sync()
            
            # 显示保存成功的提示
            # self.show_settings_saved_message()
            
            # log_event(f"设置已保存: 自动检查更新={self.auto_update_check.isChecked()}", level="INFO")
            
        except Exception as e:
            log_event(f"保存设置失败: {str(e)}", level="ERROR")
            # self.show_settings_error_message()
    
    # def show_settings_saved_message(self):
    #     """显示设置已保存的提示"""
    #     self.settings_status_label.setText("✓ 设置已保存")
    #     self.settings_status_label.setStyleSheet("color: #4CAF50; font-size: 12px;")
    #     self.settings_status_label.show()
    #     # 3秒后隐藏提示
    #     QTimer.singleShot(3000, self.settings_status_label.hide)
    
    # def show_settings_error_message(self):
    #     """显示设置保存失败的提示"""
    #     self.settings_status_label.setText("✗ 设置保存失败")
    #     self.settings_status_label.setStyleSheet("color: #f44336; font-size: 12px;")
    #     self.settings_status_label.show()
    #     # 3秒后隐藏提示
    #     QTimer.singleShot(3000, self.settings_status_label.hide)
    def create_shadow(self):
        """创建阴影效果"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)
        return shadow
    
    @Slot()
    def zpcr(self):
        path = self.zip_edit.text().strip()
        if not path:
            self.zip_status_label.setText("内容不能为空")
            self.zip_status_label.setStyleSheet("color: #f44336; font-size: 12px;")
            return
        
        if self.pj_zip(path):
            self.zip_status_label.setText("破解成功")
            self.zip_status_label.setStyleSheet("color: #4CAF50; font-size: 12px;")
            self.zip_edit.clear()
            
            # 3秒后清空状态消息
            QTimer.singleShot(3000, lambda: self.zip_status_label.setText(""))
        else:
            self.zip_status_label.setText("破解失败, 请稍后重试")
            self.zip_status_label.setStyleSheet("color: #f44336; font-size: 12px;")
    def pj_zip(self,path):
        return True

    @Slot()
    def browse_save_path(self):
        """浏览保存路径"""
        path = QFileDialog.getExistingDirectory(self, "选择保存路径")
        if path:
            self.save_path_edit.setText(path)
            self.save_settings()  # 立即保存设置
    
    @Slot()
    def reset_settings(self):
        """重置所有设置"""
        reply = QMessageBox.warning(
            self,
            "确认重置",
            "确定要重置所有高级设置吗？此操作不可撤销！",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.auto_update_check.setChecked(True)  # 默认打开
            self.log_level_combo.setCurrentText("INFO")
            self.thread_spin.setValue(4)
            self.auto_save_check.setChecked(False)
            self.save_path_edit.clear()
            # 保存重置后的设置
            self.save_settings()
            QMessageBox.information(self, "重置完成", "所有高级设置已重置为默认值")


class MainWindow(QMainWindow):
    """主窗口"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DNE-OCR文字识别")
        
        # 设置窗口属性：半透明背景和无边框
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        # 设置窗口大小
        # self.resize(770, 700)  # 增加宽度以容纳侧边栏
        # self.setMaximumHeight(630)
        self.setFixedWidth(780)
        # 设置窗口图标
        self.setWindowIcon(self.load_icon())
        self.user_manager = UserManager()
        # self.ocr_page.user_manager = self.user_manager
        # 初始化鼠标拖拽变量
        self.mouse_flag = False
        self.mouse_pos = QPoint()
        self.current_opacity = 100
        
        # 创建中央部件和堆叠窗口
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # 设置中央部件样式 - 添加阴影和背景色
        self.central_widget.setStyleSheet("""
            QWidget {
                background-color: #2c3e50;
                border-radius: 21px;
            }
        """) # 主窗口效果 圆角 背景
        
        # 为中央部件添加阴影效果
        self.shadow_effect = QGraphicsDropShadowEffect()
        self.shadow_effect.setColor(QColor(2, 2, 2, 0))
        self.shadow_effect.setOffset(3, 3)  # 添加一点偏移
        self.shadow_effect.setBlurRadius(25)  # 增加模糊半径
        self.central_widget.setGraphicsEffect(self.shadow_effect)
        
        self.main_layout = QHBoxLayout(self.central_widget)  # 改为水平布局
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # 创建右侧内容区域
        self.right_content = QWidget()
        self.right_content.setStyleSheet("""
            QWidget {
                background-color: transparent;
            }
        """)
        self.right_layout = QVBoxLayout(self.right_content)
        self.right_layout.setContentsMargins(10, 10, 10, 10)
        # self.right_content.setSizePolicy()
        
        # 创建自定义标题栏
        self.create_title_bar()
        
        # 创建堆叠窗口
        self.stacked_widget = QStackedWidget()
        self.right_layout.addWidget(self.stacked_widget)
        
        # 创建各个页面
        self.create_pages()
        
        # 设置返回按钮的回调
        self.abab_page.back_btn.clicked.connect(lambda: self.show_page_with_animation(self.ocr_btn, self.ocr_page))
        self.compressor_page.back_btn.clicked.connect(lambda: self.show_page_with_animation(self.ocr_btn, self.ocr_page))
        self.settings_page.back_btn.clicked.connect(lambda: self.show_page_with_animation(self.ocr_btn, self.ocr_page))
        self.advanced_settings_page.back_btn.clicked.connect(lambda: self.show_page_with_animation(self.settings_btn, self.settings_page))
        self.encrypt_page.back_btn.clicked.connect(lambda: self.show_page_with_animation(self.ocr_btn, self.ocr_page))
        # 连接设置页面的信号
        self.settings_page.advanced_settings_requested.connect(lambda: self.show_page_with_animation(None, self.advanced_settings_page))
        self.settings_page.exit_requested.connect(self.fade_out)
        # 创建左侧图标菜单栏 仿PYAS风格
        self.create_sidebar_menu()
        # 将右侧内容区域添加到主布局
        self.main_layout.addWidget(self.right_content)
        self.update_user_ui()
        # print( self.main_layout.sizeHint())
        # 设置窗口初始透明度为0
        self.setWindowOpacity(0)
        # 延迟显示窗口,实现淡入效果
        QTimer.singleShot(50, self.fade_in)
        if check_single_instance():
            # self.hide()
            messageboxall("警告", "已经有一个应用在运行了!","w")
            sys.exit(0)
    
    def create_pages(self):
        """创建所有页面"""
        self.ocr_page = OCRPage(self.user_manager)
        self.abab_page = AbabPage()
        self.compressor_page = TextCompressorPage()
        self.settings_page = SettingsPage()
        self.advanced_settings_page = AdvancedSettingsPage()
        self.encrypt_page = EncryptPage()
        
        # 添加页面到堆叠窗口
        self.stacked_widget.addWidget(self.ocr_page)
        self.stacked_widget.addWidget(self.abab_page)
        self.stacked_widget.addWidget(self.compressor_page)
        self.stacked_widget.addWidget(self.settings_page)
        self.stacked_widget.addWidget(self.advanced_settings_page)
        self.stacked_widget.addWidget(self.encrypt_page)
        # 默认显示OCR页面
        self.stacked_widget.setCurrentWidget(self.ocr_page)
    
    def create_sidebar_menu(self):
        """创建左侧图标菜单栏"""
        sidebar = QWidget()
        sidebar.setFixedWidth(80)  # 固定宽度
        sidebar.setStyleSheet("""
            QWidget {
                background-color: #1f2c39;
                border-top-left-radius: 10px;
                border-bottom-left-radius: 10px;
            }
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 12px;
                color: white;
                border-radius: 5px;
                font-size: 11px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: rgb(40, 134, 114);
            }
            QPushButton:pressed {
                background-color: rgb(35, 119, 101);
            }
        """)
        
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(5, 10, 5, 10)
        sidebar_layout.setSpacing(5)
        
        # 添加占位空间
        sidebar_layout.addStretch()
        
        # 创建菜单项
        menu_items = [
            ("OCR识别", self.ocr_page, True),
            ("啊哦转换", self.abab_page, False),
            ("文本压缩", self.compressor_page, False),
            ("加密工具", self.encrypt_page, False),
            ("", None, False),  # 分隔线
            ("设置", self.settings_page, False)
        ]
        
        for text, target_page, is_active in menu_items:
            if text == "":  # 分隔线
                line = QFrame()
                line.setFrameShape(QFrame.HLine)
                line.setStyleSheet("background-color: #34495e; margin: 5px 0;")
                sidebar_layout.addWidget(line)
                continue
                
            btn = QPushButton(text)
            btn.setFixedHeight(50)
            
            if is_active:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: rgb(40, 134, 114);
                        border: none;
                        padding: 12px;
                        color: white;
                        border-radius: 5px;
                        font-size: 11px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: rgb(45, 149, 127);
                    }
                """)
            
            # 连接点击事件
            if target_page:
                btn.clicked.connect(lambda checked=False, t=target_page, b=btn: self.show_page_with_animation(b, t))
            
            sidebar_layout.addWidget(btn)
            # 存储按钮引用以便后续管理选中状态
            if text == "OCR识别":
                self.ocr_btn = btn
            elif text == "啊哦转换":
                self.abab_btn = btn
            elif text == "文本压缩":
                self.compressor_btn = btn
            elif text == "设置":
                self.settings_btn = btn
            elif text == "加密工具":
                self.encrypt_btn = btn
        
        # 添加占位空间
        sidebar_layout.addStretch()
        
        # 将侧边栏添加到主布局的左侧
        self.main_layout.insertWidget(0, sidebar)
    
    def show_page_with_animation(self, button, target_page):
        """带有圆形动画效果的页面切换"""
        # 如果提供了按钮,则更新菜单选择状态
        if button:
            self.update_menu_selection(button)
        
        # 如果目标页面已经是当前页面,则不执行切换
        if self.stacked_widget.currentWidget() == target_page:
            return
        
        # 确保目标页面是可见的
        target_page.show()
        target_page.raise_()
        
        # 应用圆形切换动画
        self.animate_circle_transition(target_page)
        
        # 切换堆叠窗口的当前页面
        self.stacked_widget.setCurrentWidget(target_page)
    
    def animate_circle_transition(self, target_widget):
        """应用圆形切换动画修复闪烁问题"""
        # 获取目标窗口的大小
        w, h = target_widget.width(), target_widget.height()
        
        # 获取鼠标点击位置使用窗口中心作为动画起点
        # click_pos = QPoint(w // 2, h // 2)
        click_pos = QPoint()
        # 计算从点击位置到四个角的最大距离作为最终半径
        distances = [
            math.sqrt(click_pos.x()**2 + click_pos.y()**2),  # 左上角
            math.sqrt((w - click_pos.x())**2 + click_pos.y()**2),  # 右上角
            math.sqrt(click_pos.x()**2 + (h - click_pos.y())**2),  # 左下角
            math.sqrt((w - click_pos.x())**2 + (h - click_pos.y())**2)  # 右下角
        ]
        final_radius = int(max(distances))
        # 在动画开始时隐藏页面内容,防止闪烁
        # target_widget.setVisible(False)
        
        # 创建动画
        anim = QVariantAnimation(target_widget)
        anim.setStartValue(0)
        anim.setEndValue(final_radius)
        anim.setDuration(400)  # 动画时长300ms
        
        # 设置动画曲线
        # anim.setEasingCurve(QEasingCurve.OutCubic)
        # 先快后慢
        
        # 动画更新时更新遮罩
        def update_mask(radius):
            if radius > 0:
                # 创建圆形区域
                region = QRegion(
                    click_pos.x() - radius,
                    click_pos.y() - radius,
                    radius * 2,
                    radius * 2,
                    QRegion.Ellipse
                )
                target_widget.setMask(region)
                # 在动画期间显示页面
                # target_widget.setVisible(True)
        
        anim.valueChanged.connect(update_mask)
        
        # 动画结束时移除遮罩并确保页面完全显示
        def animation_finished():
            target_widget.clearMask()
            # target_widget.setVisible(True)
            target_widget.show()
        
        anim.finished.connect(animation_finished)
        
        # 启动动画
        anim.start()
    
    def update_menu_selection(self, selected_btn):
        """更新菜单选择状态"""
        # 重置所有按钮样式
        for btn in [self.ocr_btn, self.abab_btn, self.compressor_btn, self.settings_btn, self.encrypt_btn]:
            if btn:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        border: none;
                        padding: 12px;
                        color: white;
                        border-radius: 5px;
                        font-size: 11px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: rgb(40, 134, 114);
                    }
                """)
        
        # 设置选中按钮的样式
        if selected_btn:
            selected_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgb(40, 134, 114);
                    border: none;
                    padding: 12px;
                    color: white;
                    border-radius: 5px;
                    font-size: 11px;
                    text-align: center;
                }
                QPushButton:hover {
                    background-color: rgb(45, 149, 127);
                }
            """)
    
    def create_title_bar(self):
        """创建自定义标题栏"""
        title_bar = QWidget()
        title_bar.setStyleSheet("""
            QWidget {
                border-top-left-radius: 10px;
                background-color: #1f2c39;
                border-top-right-radius: 10px;
                padding: 5px;
            }
        """)
        title_bar.setFixedHeight(40)
        
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 0, 10, 0)
        
        # 标题
        title_label = QLabel("DNE - OCR文字识别")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 14px;
                font-weight: bold;
            }
        """)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        self.user_label = QLabel("未登录, 登录后可查看历史记录")
        self.user_label.setStyleSheet("""
            QLabel {
                color: #ff9800;
                font-weight: bold;
                margin-right: 10px;
            }
        """)
        title_layout.addWidget(self.user_label)
        
        # 登录/登出按钮
        self.login_btn = QPushButton("登录")
        self.login_btn.setFixedSize(60, 30)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: 2px solid #3498db;
                font-size: 12px;
                font-weight: bold;
                border-radius: 9px;
            }
            QPushButton:hover {
                background-color: #3498db;
            }
        """)
        self.login_btn.clicked.connect(self.show_login)
        title_layout.addWidget(self.login_btn)
        # 最小化按钮
        self.minimize_btn = QPushButton("−")
        self.minimize_btn.setFixedSize(30, 30)
        self.minimize_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
                font-size: 20px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color:rgb(40, 134, 114);
            }
        """)
        self.minimize_btn.clicked.connect(self.showMinimized)
        title_layout.addWidget(self.minimize_btn)
        
        # 关闭按钮
        self.close_btn = QPushButton("×")
        self.close_btn.setFixedSize(30, 30)
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
                font-size: 20px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #e74c3c;
            }
        """)
        self.close_btn.clicked.connect(self.fade_out)
        title_layout.addWidget(self.close_btn)
        
        self.right_layout.addWidget(title_bar)
    
    def show_login(self):
        """显示登录流程"""
        if self.user_manager.current_user:
            # 如果已经登录,显示登出选项
            reply = messageboxall("确认登出", f"确定要登出用户 {self.user_manager.current_user} 吗?", "c")
            if reply:
                self.user_manager.logout()
                self.update_user_ui()
        else:
            # 显示人机验证
            # captcha_window = DifficultCaptchaDialog(self) # 旧版
            captcha_window = provemankind4.MacDifficultCaptchaDialog(self)
            # screen_geometry = app.primaryScreen().availableGeometry()
            # dialog.move(
            #     (screen_geometry.width() - dialog.width()) // 2,
            #     (screen_geometry.height() - dialog.height()) // 2
            # )
            captcha_window.setModal(True)
            if captcha_window.exec() == 1:
                # 验证通过,显示登录对话框
                login_dialog = LoginDialog(self.user_manager, self)
                if login_dialog.exec() == QDialog.Accepted:
                    self.update_user_ui()
                    self.ocr_page.update_user_status()
    
    def update_user_ui(self):
        """更新用户界面"""
        if self.user_manager.current_user:
            self.user_label.setText(self.user_manager.current_user)
            self.user_label.setStyleSheet("""
                QLabel {
                    color: #4CAF50;
                    font-weight: bold;
                    margin-right: 10px;
                }
            """)
            self.login_btn.setText("登出")
            self.login_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: white;
                    border: 2px solid red;
                    font-size: 12px;
                    font-weight: bold;
                    border-radius: 9px;
                }
                QPushButton:hover {
                    background-color: red;
                }
            """)
        else:
            self.user_label.setText("未登录, 登录后可查看历史记录")
            self.user_label.setStyleSheet("""
                QLabel {
                    color: #ff9800;
                    font-weight: bold;
                    margin-right: 10px;
                }
            """)
            self.login_btn.setText("登录")
            self.login_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: white;
                    border: 2px solid #3498db;
                    font-size: 12px;
                    font-weight: bold;
                    border-radius: 9px;
                }
                QPushButton:hover {
                    background-color: #3498db;
                }
            """)
        self.ocr_page.update_user_status()
    
    def fade_in(self):
        """淡入效果"""
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(300)
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.start()
        self.show()
    
    def fade_out(self):
        """淡出效果"""
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(300)
        self.animation.setStartValue(1)
        self.animation.setEndValue(0)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        self.animation.finished.connect(self.close)
        self.animation.start()
    
    def mousePressEvent(self, event: QMouseEvent):
        """鼠标按下事件 - 用于窗口拖拽"""
        if event.button() == Qt.LeftButton:
            # 检查是否在标题栏区域内点击
            if event.pos().y() < 40:  # 标题栏高度
                self.mouse_flag = True
                self.mouse_pos = event.globalPosition().toPoint() - self.pos()
                # 拖拽时透明度降低
                self.setWindowOpacity(0.9)
                self.setCursor(Qt.ClosedHandCursor)
                event.accept()
    
    def mouseMoveEvent(self, event: QMouseEvent):
        """鼠标移动事件 - 窗口拖拽"""
        if self.mouse_flag:
            new_pos = event.globalPosition().toPoint() - self.mouse_pos
            self.move(new_pos)
            event.accept()
    
    def mouseReleaseEvent(self, event: QMouseEvent):
        """鼠标释放事件"""
        if event.button() == Qt.LeftButton and self.mouse_flag:
            self.mouse_flag = False
            self.setCursor(Qt.ArrowCursor)
            # 恢复透明度
            self.setWindowOpacity(1)
            event.accept()
    
    def create_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setOffset(0, 0)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(175, 175, 175))
        return shadow
    
    def load_icon(self):
        """
        加载图标,支持多种方法：
        1. 从文件加载
        2. 从资源加载
        3. 使用内置图标
        """
        # 方法1: 从文件加载图标
        icon_paths = [
            "yjtp.png",
            "icon.ico",
            "icon.png",
            resource_path("yjtp.png"),
            resource_path("icon.ico")
        ]
        
        for icon_path in icon_paths:
            if os.path.exists(icon_path):
                try:
                    icon = QIcon(icon_path)
                    if not icon.isNull():
                        return icon
                except Exception as e:
                    log_event(f"加载图标失败 {icon_path}: {e}", level="Warning")
        
        # 方法2: 使用内置图标
        print("未找到图标文件,使用默认图标")
        return QIcon.fromTheme("document-new")


def main():
    app = QApplication(sys.argv)
    # 设置组织名和应用程序名,用于QSettings
    app.setOrganizationName("DNE")
    app.setApplicationName("DNE-OCR")
    # 设置应用样式
    # app.setStyle("Fusion")
    app.styleHints().setColorScheme(Qt.ColorScheme.Dark)
    app.setStyle(QStyleFactory.create("Fusion"))
    # 设置应用程序样式表 包含QMessageBox样式
    app.setStyleSheet("""
        /* 主窗口样式 */
        QGroupBox {
            font-weight: bold;
            border: 2px solid #bdc3c7;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QComboBox, QSpinBox, QLineEdit, QCheckBox {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
            background-color: #2c3e50;
            color: white;
        }
        QComboBox:hover, QSpinBox:hover, QLineEdit:hover, QCheckBox:hover {
            border: 1px solid #4CAF50;
        }
        
        /* QMessageBox 样式 */
        QMessageBox {
            background-color: #2c3e50;
            border-radius: 10px;
        }
        QMessageBox QLabel {
            color: white;
            font-size: 14px;
            padding: 10px;
        }
        QMessageBox QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
            margin: 5px;
        }
        QMessageBox QPushButton:hover {
            background-color: #45a049;
        }
        QMessageBox QPushButton:pressed {
            background-color: #3d8b40;
        }
        /* 不同类型的按钮样式 */
        QMessageBox QPushButton[text="确定"],
        QMessageBox QPushButton[text="OK"],
        QMessageBox QPushButton[text="Yes"],
        QMessageBox QPushButton[text="是"] {
            background-color: #4CAF50;
        }
        QMessageBox QPushButton[text="取消"],
        QMessageBox QPushButton[text="Cancel"],
        QMessageBox QPushButton[text="No"],
        QMessageBox QPushButton[text="否"] {
            background-color: #f44336;
        }
        QMessageBox QPushButton[text="取消"]:hover,
        QMessageBox QPushButton[text="Cancel"]:hover,
        QMessageBox QPushButton[text="No"]:hover,
        QMessageBox QPushButton[text="否"]:hover {
            background-color: #d32f2f;
        }
        /* 警告框样式 */
        QMessageBox QLabel[text*="警告"],
        QMessageBox QLabel[text*="Warning"] {
            color: #ff9800;
            font-weight: bold;
        }
        /* 错误框样式 */
        QMessageBox QLabel[text*="错误"],
        QMessageBox QLabel[text*="Error"] {
            color: #f44336;
            font-weight: bold;
        }
        /* 信息框样式 */
        QMessageBox QLabel[text*="信息"],
        QMessageBox QLabel[text*="Info"] {
            color: #2196F3;
        }
    """)
    
    # 创建并显示主窗口
    window = MainWindow()
    window.setStyleSheet("""
        /* 主窗口样式 */
        QGroupBox {
            font-weight: bold;
            border: 2px solid #bdc3c7;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QComboBox, QSpinBox, QLineEdit, QCheckBox {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
            background-color: #2c3e50;
            color: white;
        }
        QComboBox:hover, QSpinBox:hover, QLineEdit:hover, QCheckBox:hover {
            border: 1px solid #4CAF50;
        }
        
        /* QMessageBox 样式 */
        QMessageBox {
            background-color: #2c3e50;
            border-radius: 10px;
        }
        QMessageBox QLabel {
            color: white;
            font-size: 14px;
            padding: 10px;
        }
        QMessageBox QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            min-width: 80px;
            margin: 5px;
        }
        QMessageBox QPushButton:hover {
            background-color: #45a049;
        }
        QMessageBox QPushButton:pressed {
            background-color: #3d8b40;
        }
        /* 不同类型的按钮样式 */
        QMessageBox QPushButton[text="确定"],
        QMessageBox QPushButton[text="OK"],
        QMessageBox QPushButton[text="Yes"],
        QMessageBox QPushButton[text="是"] {
            background-color: #4CAF50;
        }
        QMessageBox QPushButton[text="取消"],
        QMessageBox QPushButton[text="Cancel"],
        QMessageBox QPushButton[text="No"],
        QMessageBox QPushButton[text="否"] {
            background-color: #f44336;
        }
        QMessageBox QPushButton[text="取消"]:hover,
        QMessageBox QPushButton[text="Cancel"]:hover,
        QMessageBox QPushButton[text="No"]:hover,
        QMessageBox QPushButton[text="否"]:hover {
            background-color: #d32f2f;
        }
        /* 警告框样式 */
        QMessageBox QLabel[text*="警告"],
        QMessageBox QLabel[text*="Warning"] {
            color: #ff9800;
            font-weight: bold;
        }
        /* 错误框样式 */
        QMessageBox QLabel[text*="错误"],
        QMessageBox QLabel[text*="Error"] {
            color: #f44336;
            font-weight: bold;
        }
        /* 信息框样式 */
        QMessageBox QLabel[text*="信息"],
        QMessageBox QLabel[text*="Info"] {
            color: #2196F3;
        }
    """)
    # 应用程序退出处理
    sys.exit(app.exec())


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        log_event(f"错误:{str(e)}", level="ERROR")
        QMessageBox.critical(None, "错误", f"请将runlog.log文件发送给开发者以获取帮助!\n{str(e)}")


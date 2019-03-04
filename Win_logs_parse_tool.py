#!/usr/bin/python3
# -*- coding: utf-8 -*-

#Author: Xu Chao

# @Time    : 2019/2/26 9:33
# @Author  : Xu Chao
# @E-mail  : 531527537@qq.com
# @File    : Win_logs_parse_tool.py
# @SoftWare: PyCharm
# @Company : Ningxia Kaixinte Information Technology Co., Ltd.

import os, mmap, contextlib, argparse
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from xml.dom.minidom import parse
import xml.dom.minidom
from string import Template
import codecs

### 命令行参数解析模块 ###
parse = argparse.ArgumentParser(description="Windows日志解析工具帮助文档！")
parse.add_argument('-s', '--system', help='读取并解析指定的windows日志', action='store_true')
parse.add_argument('-f', '--file', help='指定一个evtx文件进行解析')
parse.add_argument('-d', '--dir', help='指定一个目录，解析目录下所有evtx文件(默认为系统日志文件夹)')
args = parse.parse_args()

### 常量 ###
path = 'C:\Windows\System32\winevt\Logs'    # Windows系统安全日志目录
files_list = os.listdir(path)               # 获取目录下所有文件名
head_tmp = Template('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <style>
        div{width: 70%;margin: 0 auto;}
        .table{margin-top: 15px;border: 2px solid #696969;border-radius:10px;border-collapse: separate;overflow:hidden}
        .badge{font-size: 15px;margin-left: 10px;}
    </style>
    <title>${title}</title>
</head>
<body>
    <div class="container">
''')              # HTML文件模板
str_tmp = Template('''
                <table class="table table-hover table-bordered">
                    <thead>
                        <tr>
                            <th>日志名称:</th>
                            <th colspan="3">${channel}</th>
                        </tr>
                     </thead>
                    <tbody>
                        <tr>
                            <td style="width:15%">事件ID:</td>
                            <td style="width:35%"><span class="badge badge-secondary">${eventid}</span></td>
                            <td style="width:15%">记录时间:</td>
                            <td>${systime}</td>
                        </tr>
                        <tr>
                            <td>Guid:</td>
                            <td colspan="3">${guid}</td>
                        </tr>
                        <tr>
                            <td>关键字:</td>
                            <td>${keywords}</td>
                            <td>等级:</td>
                            <td><span class="badge badge-primary">${level}</span></td>
                        </tr>
                        <tr>
                            <td>进程ID:</td>
                            <td><span class="badge badge-success">${proid}</span></td>
                            <td>线程ID:</td>
                            <td><span class="badge badge-success">${thrid}</span></td>
                        </tr>
                        <tr>
                            <td>用户ID:</td>
                            <td>${userid}</td>
                            <td>计算机:</td>
                            <td>${computer}</td>
                        </tr>
                        <tr>
                            <td>事件名称:</td>
                            <td>${eventname}</td>
                            <td>事件详情:</td>
                            <td>${info}</td>
                        </tr>                         
                    </tbody>
                </table>
                ''')
html_foot = '</div></body></html>'

### 日志文件解析模块 ###
def parse_logs(file_path):
    xml_data = ''
    with open(file_path, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0)
            # 遍历事件，创建Event事件
            for xml, record in evtx_file_xml_view(fh):
                xml_data += xml
    return xml_data    # 返回解析后的XML数据

### XML数据解析模块 ###
def XML_parse(filename):
    # 使用minidom解析器打开 XML 文档
    DOMTree = xml.dom.minidom.parse("./logs/xml/" + filename)     # 获取DOM树
    collection = DOMTree.documentElement                          # 解析DOM树

    events = collection.getElementsByTagName("Event")             # 获取Event标签，单条日志详情就是一个Event

    events_list = []
    for event in events:                                          # 遍历events，获取数据
        if event.getElementsByTagName('Provider')[0].hasAttribute("Guid"):
            Guid = event.getElementsByTagName('Provider')[0].getAttribute("Guid")
        if event.getElementsByTagName('TimeCreated')[0].hasAttribute("SystemTime"):
            SystemTime = event.getElementsByTagName('TimeCreated')[0].getAttribute("SystemTime")
        if event.getElementsByTagName('Execution')[0].hasAttribute("ProcessID"):
            ProcessID = event.getElementsByTagName('Execution')[0].getAttribute("ProcessID")
        if event.getElementsByTagName('Execution')[0].hasAttribute("ThreadID"):
            ThreadID = event.getElementsByTagName('Execution')[0].getAttribute("ThreadID")
        if event.getElementsByTagName('Security')[0].hasAttribute("UserID"):
            UserID = event.getElementsByTagName('Security')[0].getAttribute("UserID")
        if event.getElementsByTagName('Data')[0].hasAttribute('Name'):
            EventName = event.getElementsByTagName('Data')[0].getAttribute('Name')
        EventID = event.getElementsByTagName('EventID')[0].childNodes[0].data
        level = event.getElementsByTagName('Level')[0].childNodes[0].data
        Keywords = event.getElementsByTagName('Keywords')[0].childNodes[0].data
        Channel = event.getElementsByTagName('Channel')[0].childNodes[0].data
        Computer = event.getElementsByTagName('Computer')[0].childNodes[0].data
        Info = event.getElementsByTagName('Data')[0].childNodes[0].data
        events_list.append({
            'guid': Guid,
            'systime': SystemTime,
            'proid': ProcessID,
            'thrid': ThreadID,
            'userid': UserID,
            'eventid': EventID,
            'level': level,
            'keywords': Keywords,
            'channel': Channel,
            'computer': Computer,
            'eventname':EventName,
            'info':Info})
    return events_list  # 返回一个字典列表，列表长度为文件事件数

### 数据保存模块 ###
def save_data(filename,data,mod):
    # 判断是否存在文件夹，不存在则创建
    if not os.path.exists(os.getcwd() + "\\logs"):
        os.mkdir('logs')
    # 判断保存文件类型( XML or HTML ),判断方式为mod参数
    if mod == "xml":
        if not os.path.exists(os.getcwd() + "\\logs\\xml"):
            os.mkdir('logs\\xml')
        log_path = os.getcwd() + '\\logs\\xml\\' + filename + '.xml'
        with codecs.open(log_path, 'w', encoding='utf-8') as f:
            # 为XML创建一个顶级标签<Logs>,将XML数据写入文件
            f.write('<Logs filename="' + file_name + '.evtx">\n')
            f.write(data)
            f.write('</Logs>')
            f.close()
    elif mod == "html":
        xml_path = os.getcwd() + '\\logs\\' + file_name + '.html'
        # 为模板字符串赋值，循环写入文件
        with codecs.open(xml_path, 'w', encoding='utf-8') as f:
            html_head = head_tmp.substitute(title = file_name + '.evtx')
            f.write(html_head)
            for event in data:
                html_data = str_tmp.substitute(channel=event['channel'],eventid=event['eventid'],systime=event['systime'],guid=event['guid'],keywords=event['keywords'],level=event['level'],proid=event['proid'],thrid=event['thrid'],userid=event['userid'],computer=event['computer'],eventname=event['eventname'],info=event['info'])
                f.write(html_data)
            f.write(html_foot)
            f.close()

### 主模块，参数解析 ###
if __name__ == "__main__":
    # 判断参数，执行程序
    # 执行顺序: 解析evxt文件 -> 保存XML文件 -> 解析XML文件 -> 保存HTML文件
    if args.system:
        print("")
        for x in range(0, len(files_list)):
            print(str(x + 1) + ". " + files_list[x])
        print("")
        file_index = int(input("请输入要读取的文件序号："))
        file_name = files_list[file_index - 1]
        file_path = path + '\\' + file_name
        data = parse_logs(file_path)
        print('日志文件解析成功！')
        save_data(file_name[:-5],data,'xml')
        xml_list = XML_parse(file_name[:-5] + '.xml')
        print('XML数据解析成功！')
        save_data(file_name[:-5], xml_list, 'html')
        print('数据保存成功！')
    elif args.file:
        data = parse_logs(args.file)
        print('日志文件解析成功！')
        if '/' in args.file:
            file_name = args.file.split('/')[-1][:-5]
        elif '\\' in args.file:
            file_name = args.file.split('\\')[-1][:-5]
        save_data(file_name,data,'xml')
        xml_list = XML_parse(file_name + '.xml')
        print('XML数据解析成功！')
        save_data(file_name, xml_list, 'html')
        print('数据保存成功！')
    elif args.dir:
        files_list = os.listdir(args.dir)
        for file_name in files_list:
            if file_name[-5:] == '.evtx':
                file_path = args.dir + file_name
                data = parse_logs(file_path)
                save_data(file_name[:-5],data,xml)
                xml_list = XML_parse(file_name[:-5]+'.xml')
                save_data(file_name[:-5],xml_list,'html')
        print('日志文件解析成功！')
        print('XML数据解析成功！')
        print('数据保存成功！')

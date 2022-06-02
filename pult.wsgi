# -*- coding: utf-8 -*-
import os
import os.path
import sys
import uuid
import tempfile, shutil
import zipfile
import sqlite3
from io import StringIO
import json
from json2html import *
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from threading import Thread
import datetime

local_path = os.path.split(__file__)[0]
if local_path not in sys.path:
    sys.path.insert(0, local_path)

import prefs

CONFIG_NAMES = []
for name in prefs.CONFIGS:
    CONFIG_NAMES.append(name)

def read(environ):
    length = int(environ.get('CONTENT_LENGTH', 0))
    stream = environ['wsgi.input']
    body = tempfile.NamedTemporaryFile(mode='w+b')
    while length > 0:
        part = stream.read(min(length, 1024*200)) # 200KB buffer size
        if not part: break
        body.write(part)
        length -= len(part)
    body.seek(0)
    environ['wsgi.input'] = body
    return body

def array2str(arrs, sql, q=True):
    start = True
    if q:
        print("'", sep='', end='', file=sql)
    print("[", sep='', end='', file=sql)
    for line in arrs:
        if start:
            start = False
        else:
            print(",", sep='', end='', file=sql)
        if type(line) == list:
            array2str(line, sql, False)
        else:
            print('&quot;', line.replace('\n', "<br>").replace('\t', "&#9;").replace("'", "&apos;"), '&quot;', sep='', end='', file=sql)
    print("]", sep='', end='', file=sql)
    if q:
        print("'", sep='', end='', file=sql)


def prepareErrorTable(cur, output, secret, errorN = 0):
    print("<table width='100%' border=1><tr>", sep='', file=output)
    if errorN == 0:
        print("<th>N ошибки</th>", sep='', end='', file=output)
    print("<th>Ошибки, errors</th><th>Конфигурация</th><th>Расширения, extentions</th><th>Метка</th></tr>", sep='', file=output)
    for r in cur.fetchall():
        errors_json = json.loads(r[1].replace("&quot;", "\""))
        if len(r[5]) > 2:
            ext_json = json.loads(r[5].replace("&quot;", "\""))
        else:
            ext_json = None
        print("<tr", sep='', end='', file=output)
        if len(r[6]) != 0:
            print(" class='marked'", sep='', end='', file=output)
        print(">", sep='', end='', file=output)
        if errorN == 0:
            print("<td align='center'><span class='errorId'><a href='", prefs.SITE_URL, "/s" if secret else "", "/reports/",str(r[0]),"'>",str(r[0]),"</a></span></td>", sep='', end='', file=output)

        try:
            errors_txt = json2html.convert(json=errors_json, escape=0)
        except ValueError:
            erros_txt = str(errors_json)

        try:
            ext_txt = json2html.convert(json=ext_json)
        except ValueError:
            ext_txt = str(ext_json)

        print("<td>", errors_txt,"</td><td>",r[3], ", ", r[4],"</td><td>",ext_json is None if "" else ext_txt,"</td>", sep='', end='', file=output)
        if secret:
            print("<td align='center'><input type='text' size='6' id='line",str(r[0]), "' value='", r[6], "' onchange='mark(\"line",str(r[0]),"\")'/>", sep='', file=output)
        else:
            print("<td align='center'><input type='text' size='6' id='line",str(r[0]), "' disabled value='", r[6], "'/>", sep='', file=output)
        print("<span class='descTime'><br>", r[7], "<br>", r[8], "</span>", sep='', file=output)
        print("</td></tr>", sep='', file=output)

    print("</table>", sep='', file=output)



def readReport(fzip_name, environ):
    tdir = tempfile.TemporaryDirectory()

    with zipfile.ZipFile(fzip_name, 'r') as f:
        zipInfo = f.infolist()
        for member in zipInfo:
            if member.filename == 'report.json':
                f.extract(member, path=tdir.name)

    with open(tdir.name+"/report.json", "r", encoding='utf-8') as read_file:
        report = json.load(read_file)

    tdir.cleanup()

    return report

def send_mail():
    conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
    cur = conn.cursor()
    SQLPacket = "select reportStack.stackId, reportStack.configName from smtpQueue inner join reportStack on reportStack.stackId=smtpQueue.reportStackId"
    cur.execute(SQLPacket)
    errors = {}
    for r in cur.fetchall():
        if r[1] in errors:
            errors[r[1]].append(str(r[0]))
        else:
            errors[r[1]] = [str(r[0])]
    cur.close()

    try:
        s = smtplib.SMTP(prefs.SMTP_HOST, prefs.SMTP_PORT, timeout=10)
        s.set_debuglevel(1)
        #s.starttls()
        if len(prefs.SMTP_LOGIN) > 0:
            s.login(prefs.SMTP_LOGIN, prefs.SMTP_PASSWORD)
        for configName in errors:
            output = StringIO()
            print('Новые ошибки в сервисе регистрации ошибок:', sep='', end='\n', file=output)
            for r in errors[configName]:
                print('   ', prefs.SITE_DOMAIN, prefs.SITE_URL, "/s/reports/", r, sep='', end='\n', file=output)

            msg = MIMEText(output.getvalue(), 'plain', 'utf-8')
            msg['Subject'] = Header('Новые ошибки '+configName+' в сервисе регистрации ошибок', 'utf-8')
            msg['From'] = prefs.SMTP_FROM
            msg['To'] = ", ".join(prefs.CONFIGS[configName][1])
            s.sendmail(msg['From'], prefs.CONFIGS[configName][1], msg.as_string())

            cur = conn.cursor()
            SQLPacket = "delete from smtpQueue where reportStackId in (" + ",".join(errors[configName]) + ")"
            cur.execute(SQLPacket)
            cur.close()
            conn.commit();
            output.close()
    finally:
        s.quit()
        conn.close()


def application(environ, start_response):
    if environ['PATH_INFO'] == '/style.css':
        style=b'''H2 {
    font-family: Verdana, Tahoma, Arial, sans-serif;
}
H3 {
    font-family: Verdana, Tahoma, Arial, sans-serif;
}
.descTime {
    font-size: 70%;
}
.desc {
    font-weight: bold;
    color: red;
}
.errorId {
    font-weight: bold;
    color: black;
    background-color: rgb(255,200,200);
    font-family: Verdana, Tahoma, Arial, sans-serif;
    font-size: 120%;
}
table {
    display: table;
    border-collapse: separate;
    box-sizing: border-box;
    white-space: normal;
    line-height: normal;
    font-weight: normal;
    font-size: small;
    font-style: normal;
    color: -internal-quirk-inherit;
    text-align: start;
    border: 1px outset;
    border-spacing: 0px;
    border-color: grey;
    font-variant: normal;
    font-family: Verdana, Tahoma, Arial, sans-serif;
}
.marked {
    background-color: rgb(190,255,255);
}
.settings_table {
    width: 50%;
    font-family: Verdana, Tahoma, Arial, sans-serif;
}
p  {
    font-family: Verdana, Tahoma, Arial, sans-serif;
    contain: content;
}
.refli  {
    font-family: Verdana, Tahoma, Arial, sans-serif;
    list-style-type: circle;
    margin-bottom: 5px
}'''
        start_response('200 OK', [
            ('Content-Type', 'text/css; charset=utf-8'),
            ('Content-Length', str(len(style)))
        ])
        return [style]


    if environ['PATH_INFO'] == '/tables.js':
        output = StringIO()
        print('''function mark(line) {
    input = document.getElementById(line)
    var error = line.substring(4)
    var v = input.value
    var http = new XMLHttpRequest();
    http.open('POST', "''',  prefs.SITE_URL, '''/s/markError/"+error, true);
    http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

    http.onreadystatechange = function() {
        if (http.status != 200) {
            alert(http.status + " " + http.responseText);
        }
    }
    http.send(v)
    if (v.length == 0) {
        input.parentElement.parentElement.classList.remove("marked")
    } else {
        input.parentElement.parentElement.classList.add("marked")
    }
}
function selectConfig(configName) {
    if (configName != 'sn')
        document.location.href="''', prefs.SITE_URL, '''/s/errorsList/"+configName.substring(1)
    else
        document.location.href="''', prefs.SITE_URL, '''/s/errorsList"
}''', sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if environ['PATH_INFO'] == '/getInfo':
        length= int(environ.get('CONTENT_LENGTH', '0'))
        body = environ['wsgi.input'].read(length).decode('utf-8')
        query = json.loads(body)
        output = StringIO()
        needSendReport = False
        if 'test' in query:
            needSendReport = True
        elif query['configName'] in prefs.CONFIGS:
            for ver in prefs.CONFIGS[query['configName']][0]:
                if ver == query['configVersion'][:len(ver)]:
                    needSendReport = True
                    break

        if needSendReport:
            ret = '{"needSendReport":true,"userMessage":"Рекомендуем сформировать и отправить отчет разработчикам 1С:Медицина. При необходимости получения обратной связи свяжитесь с линией консультации по адресу med@1c.ru"}'.encode('UTF-8')
        else:
            ret = b'{"needSendReport":false}'
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if environ['PATH_INFO'] == '/pushReport':
        fzip = read(environ)
        report = readReport(fzip.name, environ)

        if not 'configInfo' in report:
            raise Exception("There is no information about configuration")

        if not 'errors' in report['errorInfo']['applicationErrorInfo']:
            raise Exception("There is no information about errors")

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.cursor()

        prev_reports = None
        if 'systemInfo' in report['clientInfo'] and 'additionalFiles' not in report:
            sql = StringIO()
            print("select report.rowid, report.count, report.userDescription from report inner join reportStack on reportStackId=stackId where stackHash='", sep='', end='', file=sql)
            print(report['errorInfo']['applicationErrorInfo']['stackHash'], "' and clientID='", sep='', end='', file=sql)
            print(report['clientInfo']['systemInfo']['clientID'], "' and configName='", sep='', end='', file=sql)
            print(report['configInfo']['name'], "' and configVersion='", sep='', end='', file=sql)
            print(report['configInfo']['version'], "'", sep='', end='', file=sql)
            if 'extentions' in report['configInfo']: 
                print(" and extentions=", sep='', end='', file=sql)
                array2str(report['configInfo']['extentions'], sql)
            else:
                print(" and extentions=''", sep='', end='', file=sql)
            print(" and errors=", sep='', end='', file=sql)
            array2str(report['errorInfo']['applicationErrorInfo']['errors'], sql)

            cur = conn.cursor()
            cur.execute(sql.getvalue())
            prev_reports = cur.fetchone()
            cur.close()
            sql.close()

        send_email = False
        if prev_reports is not None:
            if prev_reports[2] is not None and 'userDescription' in report['errorInfo']:
                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                SQLPacket += prev_reports[2] +"<br><span class=\"descTime\">"+report['time']+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>"
            elif prev_reports[2] is None and 'userDescription' in report['errorInfo']:
                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                SQLPacket += "<span class=\"descTime\">"+report['time']+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>"
            else:
                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']
            SQLPacket += "' where rowid="+str(prev_reports[0])

            cur = conn.cursor()
            cur.execute(SQLPacket)
            cur.close()
        else:
            sql = StringIO()
            print("select stackId from reportStack where stackHash='", sep='', end='', file=sql)
            print(report['errorInfo']['applicationErrorInfo']['stackHash'], "' and configName='", sep='', end='', file=sql)
            print(report['configInfo']['name'], "' and configVersion='", sep='', end='', file=sql)
            print(report['configInfo']['version'], "'", sep='', end='', file=sql)
            if 'extentions' in report['configInfo']: 
                print(" and extentions=", sep='', end='', file=sql)
                array2str(report['configInfo']['extentions'], sql)
            else:
                print(" and extentions=''", sep='', end='', file=sql)
            print(" and errors=", sep='', end='', file=sql)
            array2str(report['errorInfo']['applicationErrorInfo']['errors'], sql)

            cur = conn.cursor()
            cur.execute(sql.getvalue())
            stack = cur.fetchone()
            cur.close()
            sql.close()
            if stack is not None:
                stack = stack[0]
            else:
                sql = StringIO()
                print("insert into reportStack (errors,stackHash,configName,configVersion,extentions,marked) values (", sep='', end='', file=sql)
                array2str(report['errorInfo']['applicationErrorInfo']['errors'], sql)
                print(",'", report['errorInfo']['applicationErrorInfo']['stackHash'], sep='', end='', file=sql)
                print("','", report['configInfo']['name'], sep='', end='', file=sql)
                print("','", report['configInfo']['version'],"',", sep='', end='', file=sql)
                if 'extentions' in report['configInfo']: 
                    array2str(report['configInfo']['extentions'], sql)
                else:
                    print("''", file=sql)

                print(",'')", sep='', end='', file=sql)
                cur = conn.cursor()
                cur.execute(sql.getvalue())
                sql.close()

                sql = StringIO()
                print("select stackId from reportStack where stackHash='", sep='', end='', file=sql)
                print(report['errorInfo']['applicationErrorInfo']['stackHash'] + "' and configName='", sep='', end='', file=sql)
                print(report['configInfo']['name'], "' and configVersion='", sep='', end='', file=sql)
                print(report['configInfo']['version'],"'", sep='', end='', file=sql)
                if 'extentions' in report['configInfo']: 
                    print(" and extentions=", sep='', end='', file=sql)
                    array2str(report['configInfo']['extentions'], sql)
                else:
                    print(" and extentions=''", sep='', end='', file=sql)
                print(" and errors=", sep='', end='', file=sql)
                array2str(report['errorInfo']['applicationErrorInfo']['errors'], sql)
                cur = conn.cursor()
                cur.execute(sql.getvalue())
                stack = cur.fetchone()[0]
                cur.close()
                sql.close()

                if len(prefs.SMTP_HOST) > 0 and len(prefs.SMTP_FROM) > 0 and report['configInfo']['name'] in prefs.CONFIGS and len(prefs.CONFIGS[report['configInfo']['name']][1]) > 0:
                    send_email = True
                    sql = StringIO()
                    print("insert into smtpQueue values (", stack, ")", sep='', end='', file=sql)
                    cur = conn.cursor()
                    cur.execute(sql.getvalue())
                    sql.close()

            fn = str(uuid.uuid4())+".zip"
            sql = StringIO()
            print("insert into report values ('", report['time'],"','", sep='', end='', file=sql)
            print(report['sessionInfo']['userName'] if 'userName' in report['sessionInfo'] else "","','", sep='', end='', file=sql)
            print(report['clientInfo']['appVersion'],"','", sep='', end='', file=sql)
            print(report['clientInfo']['platformType'],"','", sep='', end='', file=sql)
            print(report['serverInfo']['type'],"','", sep='', end='', file=sql)
            print(report['sessionInfo']['dataSeparation'],"','", sep='', end='', file=sql)
            print(report['serverInfo']['dbms'],"','", sep='', end='', file=sql)
            if 'systemInfo' in report['clientInfo']:
                print(report['clientInfo']['systemInfo']['clientID'], sep='', end='', file=sql)
            print("',", sep='', end='', file=sql)
            print("1,'", sep='', end='', file=sql)
            print(fn,"',", sep='', end='', file=sql)
            print(1 if report['configInfo']['changeEnabled'] else 0,",", sep='', end='', file=sql)
            print(stack, ",", sep='', end='', file=sql)
            if 'userDescription' in report['errorInfo']:
                print("'<span class=\"descTime\">", report['time'], "</span>&nbsp;<span class=\"desc\">", report['errorInfo']['userDescription'], "</span>',", sep='', end='', file=sql)
            else:
                print("NULL,", sep='', end='', file=sql)
            print("'", environ['REMOTE_ADDR'],"',", sep='', end='', file=sql)
            print(1 if 'additionalFiles' in report else 0, sep='', end='', file=sql)
            print(")", sep='', end='', file=sql)

            cur = conn.cursor()
            cur.execute(sql.getvalue())

            shutil.copy(fzip.name, prefs.DATA_PATH+"/"+fn)
            sql.close()

        conn.commit()

        if send_email:
            Thread(target=send_mail, args=()).start()

        conn.close()
        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', '0')
        ])
        return b""


    if environ['PATH_INFO'] == '/s/settings':
        output = StringIO()
        print('''<html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css">
<title>Настройки сервиса регистрации ошибок 1С:Медицина</title>
</head><body><H2>Настройки сервиса регистрации ошибок</H2>
<p>Конфигурации и их версии, по которым принимаются отчеты об ошибках - </p>''', json2html.convert(json=prefs.CONFIGS, table_attributes="border=1 class='settings_table'"), '''
<p>В словаре (dict) ключ - имя конфигурации, значение - массив из 2-х массивов.</p>
<ul><li class='refli'>1-й список - список допустимых версий. Если список пустой, то отчеты не принимаются.
Пустая строка в версия - принимаются любые версии. Неполное задание версии допускатся.</li>
<li class='refli'>2-й список - список email, которым будет отправлено сообщение о регистрации новой ошибки.</li></ul>
<p>Отчет считается новой ошибкой, если образуется уникальная комбинация из следующих данных из отчета:</p>
<ul><li class='refli'>Наименование конфигурации</li>
<li class='refli'>Версия конфигурации</li>
<li class='refli'>Установленные расширения</li>
<li class='refli'>Текст ошибки</li>
<li class='refli'>Хеш стека ошибки конфигурации</li></ul>
<p>Если список пустой, то почта для этой конфигурации не отправляется.</p>''', sep='', file=output)

        print("<hr>Для изменения настроек необходимо изменить значения соответствующих переменных в файле prefs.py. После чего перестартовать апач.", sep='', file=output)
        print("<hr><h3>Перейти:</h3>", sep='', file=output)
        print("<ul><li class='refli'><a href='", prefs.SITE_URL, "/s" if secret else "", "/errorsList'>Список ошибок</a></lu>", sep='', file=output)
        print("<li class='refli'><a href='", prefs.SITE_URL, "/s/clear'>Удаление отчетов неподдерживаемых версий и конфигураций</a></li>", sep='', file=output)
        print("</ul></body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if environ['PATH_INFO'] == '/s/clear':
        output = StringIO()
        print('<html><head>', sep='', end='', file=output)
        print("<meta charset='utf-8'>", sep='', file=output)
        print("<link rel='stylesheet' href='", prefs.SITE_URL, "/style.css'>", sep='', file=output)
        print("<title>Удаление отчетов неподдерживаемых версий и конфигураций</title>", sep='', file=output)
        print("</head><body><h2>Удаление отчетов неподдерживаемых версий и конфигураций</h2>", sep='', file=output)
        print("<p>Поддерживаемые конфигурации - ", json2html.convert(json=prefs.CONFIGS, table_attributes="border=1 class='settings_table'"), "</p>", sep='', file=output)
        print("<hr><h3>Перейти:</h3><p><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></p>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.cursor()

        stackIds = ""
        errorsCount = 0
        for name in prefs.CONFIGS:
            sql = StringIO()
            print("select stackId from reportStack where configName='", name,"'", sep='', end='', file=sql)
            for ver in prefs.CONFIGS[name][0]:
                print(" and configVersion not like '", ver,"%'", sep='', end='', file=sql)
            cur = conn.cursor()
            cur.execute(sql.getvalue())

            start = True
            for r in cur.fetchall():
                if not start:
                    print(",", sep='', end='', file=sql)
                else:
                    start = False
                stackIds += str(r[0])
                errorsCount += 1
            cur.close()
            sql.close()

        sql = StringIO()
        print("select file from report where reportStackId in (", stackIds, ")", sep='', end='', file=sql)
        cur = conn.cursor()
        cur.execute(sql.getvalue())
        reportsCount = 0
        for r in cur.fetchall():
            os.remove(prefs.DATA_PATH+"/"+r[0])
            reportsCount += 1
        cur.close()
        sql.close()

        sql = StringIO()
        print("delete from report where reportStackId in (", stackIds, ")", sep='', end='', file=sql)
        cur = conn.cursor()
        cur.execute(sql.getvalue())
        cur.close()
        sql.close()

        sql = StringIO()
        print("delete from reportStack where stackId in (", stackIds, ")", sep='', end='', file=sql)
        cur = conn.cursor()
        cur.execute(sql.getvalue())
        cur.close()
        sql.close()

        conn.commit()
        conn.close()

        print("<H3>Удалено ошибок: ", errorsCount, ", отчетов: ", reportsCount, "</H3>", sep='', file=output)
        print("</body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    url = environ['PATH_INFO'].split('/')
    secret = True if url[1] == 's' else False
    if secret:          # все нижелащие url могут находится в зоне с ограниченным доступом, префикс может быть равен 's'
        s = url.pop(0)

    if len(url) in [2,3] and url[1] == 'errorsList' and (len(url) == 2 or url[2].isdigit()):
        output = StringIO()
        print('''<html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css"/>
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Список ошибок сервиса регистрации ошибок 1С:Медицина</title>
</head><body><H2>Список ошибок сервиса регистрации ошибок</H2>''', sep='', file=output)

        if secret:
            print("<br><p>Фильтр на конфигурацию: <select name='configName' size='1' onchange='selectConfig(this.value)'>", sep='', file=output)
            if len(url) == 2:
                print("<option value='sn' selected/>", sep='', file=output)
            else:
                print("<option value='sn'/>", sep='', file=output)
            for i in range(len(CONFIG_NAMES)):
                if len(url) == 3 and i == int(url[2]):
                    print("<option value='s", i, "' selected>", CONFIG_NAMES[i], "</option>", sep='', file=output)
                else:
                    print("<option value='s", i, "'>", CONFIG_NAMES[i], "</option>", sep='', file=output)
            print("</select></p>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=OFF;")
        cur = conn.cursor()
        if len(url) == 2:
            SQLPacket = "select * from reportStack order by stackId desc"
        else:
            SQLPacket = "select * from reportStack where configName='"+CONFIG_NAMES[int(url[2])]+"' order by stackId desc"
        cur = conn.cursor()
        cur.execute(SQLPacket)
        prepareErrorTable(cur, output, secret)
        cur.close()
        conn.close()

        print('''<p><a href='https://its.1c.ru/db/v8320doc#bookmark:dev:TI000002262'>Документация на ИТС по отчету об ошибке</a></p>
<p><a href="''', prefs.SITE_URL, '''/s/settings">Настройки сервиса</a></p>
</body></html>''', sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if secret and len(url) == 3 and url[1] == 'markError' and url[2].isdigit():         # только закрытая зона так как измение отметки
        output = StringIO()
        length= int(environ.get('CONTENT_LENGTH', '0'))
        value = environ['wsgi.input'].read(length).decode('utf-8')

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=OFF;")

        cur = conn.cursor()
        SQLPacket = "select marked from reportStack where stackId="+url[2]
        cur = conn.cursor()
        cur.execute(SQLPacket)
        err = cur.fetchone()
        cur.close()

        if err is None:
            raise Exception("Error - '"+url[2]+"' not found")

        if err[0] != value:
            user = "" if 'REMOTE_USER' not in environ else environ['REMOTE_USER']
            SQLPacket = "update reportStack set marked='"+value+"', markedTime='"+datetime.datetime.now().strftime('%d.%m.%y %H:%M')+"', markedUser='"+user+"' where stackId="+url[2]
            cur = conn.cursor()
            cur.execute(SQLPacket)
            cur.close()
            conn.commit()
        conn.close()

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if len(url) == 3 and url[1] == 'reports' and url[2].isdigit():      # список отчетов в открытой и закрытой зонах
        output = StringIO()
        print('''<html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css"/>
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Список отчетов сервиса регистрации ошибок 1С:Медицина</title>''', sep='', end='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=OFF;")

        print("</head><body><h2>Ошибка <span class='errorId'>", url[2], "</span></h2>", sep='', file=output)

        cur = conn.cursor()
        SQLPacket = "select * from reportStack where stackId="+url[2]
        cur = conn.cursor()
        cur.execute(SQLPacket)
        prepareErrorTable(cur, output, secret, url[2])
        cur.close()

        print('''<br><h3>Отчеты</h3><table width='100%' border=1><tr>
<th>Дата</th>
<th>Пользователь 1С</th>
<th>IP адрес</th>
<th>Версия платформы</th>
<th>Платформа клиента</th>
<th>Платформа сервера</th>
<th>dataSeparation</th>
<th>СУБД</th>
<th>changeEnabled</th>
<th>Описание пользователя</th>
<th>Число отчетов</th></tr>''', sep='', file=output)
        cur = conn.cursor()
        SQLPacket = "select * from report where reportStackId="+url[2]+" order by rowid desc"
        cur = conn.cursor()
        cur.execute(SQLPacket)
        found = False
        for r in cur.fetchall():
            print("<tr><td><span class='descTime'>", r[0], "</span></td><td>", r[1], "</td><td>", r[13], "</td><td>", r[2], "</td><td>",r[3],"</td><td>", r[4],"</td><td>",r[5],"</td><td>", r[6],"</td><td align='center'>",r[10],"</td><td>","" if r[12] is None else r[12],"</td><td align='center'>","<a href='",prefs.SITE_URL,"/s" if secret else "","/report/",r[9],"'>",'Файл(ы)' if r[14]==1 else r[8],"</a></td></tr>", sep='', file=output)
            found = True

        cur.close()
        conn.close()
        print("</table>", sep='', file=output)


        if not found:
            output = StringIO()
            print('''<html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css"/>
<title>Список отчетов сервиса регистрации ошибок 1С:Медицина</title>''', sep='', end='', file=output)
            print("</head><body><h2>Ошибка <span class='errorId'>", url[2], "</span> Не найдена</h2>", sep='', file=output)

        print('''<p><a href='https://its.1c.ru/db/v8320doc#bookmark:dev:TI000002262'>Документация на ИТС по отчету об ошибке</a></p>
<p><a href="''', prefs.SITE_URL, "/s" if secret else "", '''/errorsList">Список ошибок</a></p>''', sep='', file=output)
        print("</body></html>", sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if len(url) == 3 and url[1] == 'report':    # отчет в открытой и закрытой зонах
        status = '200 OK'
        response_headers = [('Content-type', 'application/zip')]
        start_response(status, response_headers)
        f = open(prefs.DATA_PATH+'/'+url[2], 'rb')
        block_size = 4096

        if 'wsgi.file_wrapper' in environ:
            return environ['wsgi.file_wrapper'](f, block_size)
        else:
            return iter(lambda: filelike.read(block_size), '')

    else:
        start_response('404 Not Found', [('Content-Type','text/html; charset=utf-8')])
        return [b'<p>Page Not Found</p>'+environ['PATH_INFO'].encode('UTF-8')+b'\n']


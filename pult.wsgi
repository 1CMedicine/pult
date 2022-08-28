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
import re

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


def array2str(arrs, sql):
    start = True
    print("[", sep='', end='', file=sql)
    for line in arrs:
        if start:
            start = False
        else:
            print(",", sep='', end='', file=sql)
        if type(line) == list:
            array2str(line, sql)
        else:
            print('"', line.replace("\"", "&#34;").replace('\n', "<br>").replace('\t', "&#9;").replace("'", "&apos;").replace('\\', "&#92;"), '"', sep='', end='', file=sql)
    print("]", sep='', end='', file=sql)


def prepareErrorTableLine(r, output, secret, issueN):
    print("<tr", sep='', end='', file=output)
    if len(r[6]) != 0:
        print(" class='marked'", sep='', end='', file=output)
    print(">", sep='', end='', file=output)
    if issueN == 0:
        print("<td align='center'><span class='errorId'><a href='", prefs.SITE_URL, "/s" if secret else "", "/reports/",str(r[0]),"'>",str(r[0]),"</a></span></td>", sep='', file=output)

    errors_txt = r[1]+"<br><br>"
    try:
        errors_json = json.loads(r[1])
        errors_txt = json2html.convert(json=errors_json, escape=0)
    except:
        erros_txt = r[1]

    print("<td style='word-wrap: break-word'>",errors_txt,"Хеш стека: ",r[2],"</td>",  file=output)
    print("<td style='word-wrap: break-word;vertical-align: top;'>","<br>".join(r[3]),"</td>", sep='',  file=output)
    if secret:
        print("<td align='center'><input type='text' size='10' id='line",str(r[0]), "' value='", r[6], "' onchange='mark(\"line",str(r[0]),"\")'/>", sep='', file=output)
        print("<br><small><a href='", prefs.SITE_URL,"/s/delete/",str(r[0]), "' ",'''onclick='return confirm("Вы уверены?")'>удалить</a></small>''', sep='', file=output)
    else:
        print("<td align='center'><input type='text' size='10' id='line",str(r[0]), "' disabled value='", r[6], "'/>", sep='', file=output)
    print("<span class='descTime'><br>", r[7], "<br>", r[8], "</span>", sep='', file=output)
    print("</td></tr>", sep='', file=output)


# строит html таблицу с описанием ошибок или таблицу для одной ошибки с номером issueN
# возвращает список stackId, присутствующих в выборке. Используется только если issueN != 0, а значит stackId последней и единственной записи.
# При построении таблицы выполняется группировка по номеру ошибки. Записи сортированные.
def prepareErrorTable(cur, output, secret, issueN = 0):
    print("<table style='width: 100%; table-layout : fixed;' border=1><tr>", sep='', file=output)
    if issueN == 0:
        print("<th style='width: 3%'>N</th>", sep='', end='', file=output)
    print("<th style='width: 60%'>Ошибки, errors</th><th style='width: 30%'>Конфигурация, версия и расширения</th><th style='width: 7%'>Метка</th></tr>", sep='', file=output)
    pr = None
    prev_issueN = 0
    r = None
    stackId = []
    for r in cur.fetchall():
        conf = r[3]+", "+r[4]
        id = str(r[9])
        stackId.append(id)
        if len(r[5]) > 2:
            ext_json = json.loads(r[5])
            try:
                ext_txt = json2html.convert(json=ext_json)
            except ValueError:
                ext_txt = str(ext_json)
            conf += '<details><summary>'+str(len(ext_json))+' расширений</summary>'+ext_txt+"</details>\n"

        if prev_issueN != r[0]:
            if pr is not None:
                prepareErrorTableLine(pr, output, secret, issueN)
            prev_issueN = r[0]
            pr = list(r)
            pr[3] = [conf]
        else:
            pr[3].append(conf)

    if pr is not None:
        prepareErrorTableLine(pr, output, secret, issueN)
    print("</table>", sep='', file=output)

    return stackId


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
    SQLPacket = "select smtpQueue.issueId, reportStack.configName from smtpQueue inner join reportStack on reportStack.issueId=smtpQueue.issueId"
    cur.execute(SQLPacket)
    errors = {}
    for r in cur.fetchall():
        if r[1] in errors:
            errors[r[1]].append(str(r[0]))
        else:
            errors[r[1]] = [str(r[0])]
    cur.close()

    try:
        s = None
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
            SQLPacket = "delete from smtpQueue where issueId in (" + ",".join(errors[configName]) + ")"
            cur.execute(SQLPacket)
            cur.close()
            conn.commit();
            output.close()
    finally:
        if s is not None:
            s.quit()
        conn.close()


def insertReportStack(conn, report, issueId):
    t = StringIO()
    if 'extentions' in report['configInfo']:
        array2str(report['configInfo']['extentions'], t)
    else:
        print("", sep='', end='', file=t)

    i = (issueId, report['configInfo']['name'], report['configInfo']['version'], t.getvalue()) 
    cur = conn.cursor()
    cur.execute("select stackId from reportStack where issueId=? and configName=? and configVersion=? and extentions=?", i)
    t = cur.fetchone()
    cur.close()
    stackId = t[0] if t is not None else None

    if stackId is None:
        cur = conn.cursor()
        cur.execute("insert into reportStack (issueId,configName,configVersion,extentions) values (?,?,?,?)", i)
        cur.close()

        cur = conn.cursor()
        cur.execute("select stackId from reportStack where issueId=? and configName=? and configVersion=?  and extentions=?", i)
        stackId = cur.fetchone()[0]
        cur.close()

    return stackId


def insertReport(conn, report, stackId, fn, environ):
    i = (report['time'], 
        report['sessionInfo']['userName'] if 'userName' in report['sessionInfo'] else "", 
        report['clientInfo']['appVersion'], 
        report['clientInfo']['platformType'], 
        report['serverInfo']['type'], 
        report['sessionInfo']['dataSeparation'], 
        report['serverInfo']['dbms'],
        report['clientInfo']['systemInfo']['clientID'] if 'systemInfo' in report['clientInfo'] else "",
        1,
        fn,
        1 if report['configInfo']['changeEnabled'] else 0,
        stackId,
        "<span class=\"descTime\">" + report['time'] + "</span>&nbsp;<span class=\"desc\">" + report['errorInfo']['userDescription'] + "</span>" if 'userDescription' in report['errorInfo'] and report['errorInfo']['userDescription'] != '' else None,
        environ['REMOTE_ADDR'],
        1 if 'additionalFiles' in report or ('screenshot' in report and report['screenshot'] is not None) or 'additionalData' in report else 0)

    cur = conn.cursor()
    cur.execute("insert into report values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", i)
    cur.close()


def inStopLists(environ):
    blocked = False
    addr = environ['REMOTE_ADDR']
    for bl in prefs.BLACKLIST:
        if addr[:len(bl)] == bl:
            blocked = True
            print("Address blocked by blacklist - ", addr, sep='', end='', file=environ['wsgi.errors'])
            break
    if not blocked and len(prefs.WHITELIST) > 0:
        blocked = True
        for wl in prefs.WHITELIST:
            if addr[:len(wl)] == wl:
                blocked = False
                break
        if blocked:
            print("Address blocked by whitelist - ", addr, sep='', end='', file=environ['wsgi.errors'])
    return blocked


def platformError(errors, environ):
    try:
        if errors[-1][0].startswith('При работе формы произошла системная ошибка'):
            print("p1:", str(errors[-1]), file=environ["wsgi.errors"])
            return True

        if len(errors[-1][1]) > 0 and errors[-1][1][0] == "NetworkError":        # ошибка обмена по сети
            print("p2:", str(errors[-1]), file=environ["wsgi.errors"])
            return True

        if len(errors) > 1 and errors[1][0].startswith('Ошибка передачи данных между клиентом и сервером'):
            print("p3:", str(errors[1]), file=environ["wsgi.errors"])
            return True
    except:
        print(str(errors), file=environ["wsgi.errors"])
        raise

    return False


def errorInConf(errors, stack, environ):
    try:
        e = errors[0][0]
        if e.startswith('{ВнешняяОбработка.') or e.startswith('{ВнешнийОтчет.'):
            print("e1:", e, file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Недостаточно прав') or (len(errors[-1][1]) > 0 and errors[-1][1][0] == "AccessViolation"):
            print("r1:", str(errors[-1]), file=environ["wsgi.errors"])
            return False

        #Ошибка в расширении
        dot = e.find('.')
        if dot != -1:
            space = e.find(' ', 2, dot)
            if space != -1 and not e.startswith('{E'):    # расширение, но не патч
                print("e2:", e, file=environ["wsgi.errors"])
                return False

            dot2 = e.find('.', dot+1)
            if dot2 != -1:
                if e.find('_', dot+1, dot2) != -1:    # в имени объекта метаданных есть подчеркиавание, значит объект нетиповой
                    print("e3:", e, file=environ["wsgi.errors"])
                    return False
    except:
        print(str(errors), file=environ["wsgi.errors"])
        raise

    # Вызов из объекта пользователя
    try:
        s = stack[0][0]
        if s.startswith('ВнешняяОбработка.') or s.startswith('ВнешнийОтчет.'):
            print("s4:", s, file=environ["wsgi.errors"])
            return False

        for s1 in stack:
            s = s1[0]
            dot = s.find('.')
            if dot != -1:
                space = s.find(' ', 1, dot)
                if space != -1 and not s.startswith('E'):   #расширение, но не патч
                    print("s5:", s, file=environ["wsgi.errors"])
                    return False

                dot2 = s.find('.', dot+1)
                if dot2 != -1:
                    if s.find('_', dot+1, dot2) != -1:    # в имени объекта метаданных есть подчеркивание, значит объект нетиповой
                        print("s6:", s, file=environ["wsgi.errors"])
                        return False
    except:
        print(str(stack), file=environ["wsgi.errors"])
        raise

    return True


def application(environ, start_response):
    if environ['PATH_INFO'] == '/style.css':
        style = b'''H2 {
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
}
details {
display:inline;
}
details > summary {
font-size: 10px;
background-color: lightgrey;
padding: 0px;
margin: 0px 10px 5px 10px;
}
'''
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
}
''', sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if environ['PATH_INFO'] == '/getInfo':
        needSendReport = False
        if not inStopLists(environ):
            try:
                length = int(environ.get('CONTENT_LENGTH', '0'))
            except (ValueError):
                length = 0
            body = environ['wsgi.input'].read(length).decode('utf-8')
            if len(body) > 1:
                query = json.loads(body)
                output = StringIO()
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

        #  Если IP не в стоплисте и нет стека, ошибки или информации и конфе или ошибка во внешнх объектах, то игнорируем отчет, так как нам интересны только ошибки модулей нашей конфы
        full_data = ('stackHash' in report['errorInfo']['applicationErrorInfo'] and 'errors' in report['errorInfo']['applicationErrorInfo'] and 'configInfo' in report)
        in_stop = inStopLists(environ)
        in_conf = None
        platform = None
        if full_data and not in_stop:
            in_conf = not prefs.ONLY_IN_CONF or errorInConf(report['errorInfo']['applicationErrorInfo']['errors'], report['errorInfo']['applicationErrorInfo']['stack'], environ)
            if in_conf:
                platform = platformError(report['errorInfo']['applicationErrorInfo']['errors'], environ)
        if full_data and not in_stop and in_conf and not platform:
            stackHash = report['errorInfo']['applicationErrorInfo']['stackHash']

            conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
            conn.execute("PRAGMA foreign_keys=ON;")
            cur = conn.cursor()

            prev_issue = None
            te = StringIO()

            # схлапываем те строки, которые размножают одну ошибку в отчетах
            array2str(report['errorInfo']['applicationErrorInfo']['errors'], te)
            errors = re.sub(r"&apos;file://.*?&apos;", r"file://[path]", te.getvalue())

            cur = conn.cursor()
            cur.execute("select rowid from issue where stackHash=? and errors=?", (stackHash, errors))
            issue = cur.fetchone()
            cur.close()

            fn = str(uuid.uuid4())+".zip"
            needSendMail = False
            needStoreReport = False
            if issue is None:
                cur = conn.cursor()
                cur.execute("insert into issue (stackHash, errors) values (?,?)", (stackHash, errors))
                cur.close()

                cur = conn.cursor()
                cur.execute("select issueId from issue where stackHash=? and errors=?", (stackHash, errors))
                issue = cur.fetchone()[0]
                cur.close()

                stack = insertReportStack(conn, report, issue)
                insertReport(conn, report, stack, fn, environ)
                needStoreReport = True

                if len(prefs.SMTP_HOST) > 0 and len(prefs.SMTP_FROM) > 0 and report['configInfo']['name'] in prefs.CONFIGS and len(prefs.CONFIGS[report['configInfo']['name']][1]) > 0:
                    cur = conn.cursor()
                    cur.execute("insert into smtpQueue values (?)", (issue,))
                    needSendMail = True
                    cur.close()
            else:
                issue = issue[0]

                prev_reports = None
                if 'systemInfo' in report['clientInfo'] and 'additionalFiles' not in report and 'additionalData' not in report and 'screenshot' not in report:
                    t = StringIO()
                    if 'extentions' in report['configInfo']: 
                        array2str(report['configInfo']['extentions'], t)

                    i = (issue, report['clientInfo']['systemInfo']['clientID'], report['configInfo']['name'], report['configInfo']['version'], t.getvalue())
                    cur = conn.cursor()
                    cur.execute("select report.rowid, report.count, report.userDescription from report inner join reportStack on reportStackId=stackId where issueId=? and clientID=? and configName=? and configVersion=? and extentions=?", i)
                    prev_reports = cur.fetchone()
                    cur.close()

                    if prev_reports is not None:
                        if prev_reports[2] is not None and 'userDescription' in report['errorInfo'] and report['errorInfo']['userDescription'] != '':
                            SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                            SQLPacket += prev_reports[2] +"<br><span class=\"descTime\">"+report['time']+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>'"
                        elif prev_reports[2] is None and 'userDescription' in report['errorInfo'] and report['errorInfo']['userDescription'] != '':
                            SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                            SQLPacket += "<span class=\"descTime\">"+report['time']+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>'"
                        elif prev_reports[2] is not None: 
                            SQLPacket = "update report set count="+str(prev_reports[1]+1)+", userDescription='"+prev_reports[2] +"<br><span class=\"descTime\">"+report['time']+"</span>'"
                        else:
                            SQLPacket = "update report set count="+str(prev_reports[1]+1)+", userDescription='<span class=\"descTime\">"+report['time']+"</span>'"
                        SQLPacket += " where rowid="+str(prev_reports[0])

                        cur = conn.cursor()
                        cur.execute(SQLPacket)
                        cur.close()
                    else:
                        stack = insertReportStack(conn, report, issue)
                        insertReport(conn, report, stack, fn, environ)
                        needStoreReport = True
                else:
                    stack = insertReportStack(conn, report, issue)
                    insertReport(conn, report, stack, fn, environ)
                    needStoreReport = True

            conn.commit()
            conn.close()
            if needSendMail:
                Thread(target=send_mail, args=()).start()

            if needStoreReport:
                shutil.copy(fzip.name, prefs.DATA_PATH+"/"+fn)

        else:
            t = StringIO()
            if not full_data:
                print("(stackHash-", 'stackHash' in report['errorInfo']['applicationErrorInfo'], ", errors-", 'errors' in report['errorInfo']['applicationErrorInfo'], ", configInfo-", 'configInfo' in report, ")", sep="", end="", file=t)
            print("report filtered: stopList - ", in_stop, ", full_data - ", full_data, t.getvalue(), ", in_conf - ", in_conf, ", platform - ", platform, sep='', end='', file=environ["wsgi.errors"])

        start_response('200 OK', [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', '0')
        ])
        return b""


    if environ['PATH_INFO'] == '/s/settings':
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
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
<ul>
<li class='refli'>Текст ошибки</li>
<li class='refli'>Хеш стека ошибки конфигурации</li></ul>
<p>Если список email пустой, то почта для этой конфигурации не отправляется.</p>''', sep='', file=output)

        print("<hr>Для изменения настроек необходимо изменить значения соответствующих переменных в файле prefs.py. После чего перестартовать апач.", sep='', file=output)
        print("<hr><p>Черный список IP-адресов</p>", prefs.BLACKLIST, sep='', file=output)
        print("<p>Белый список IP-адресов</p>", prefs.WHITELIST, sep='', file=output)
        print("<hr><h3>Перейти:</h3>", sep='', file=output)
        print("<ul><li class='refli'><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></lu>", sep='', file=output)
        print("<li class='refli'><a href='", prefs.SITE_URL, "/s/clear'>Удаление отчетов неподдерживаемых версий и конфигураций, ошибок от IP из черного списка</a></li>", sep='', file=output)
        print("</ul></body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if environ['PATH_INFO'] == '/s/clear':
        output = StringIO()
        print('<!DOCTYPE html><html><head>', sep='', end='', file=output)
        print("<meta charset='utf-8'>", sep='', file=output)
        print("<link rel='stylesheet' href='", prefs.SITE_URL, "/style.css'>", sep='', file=output)
        print("<title>Удаление отчетов неподдерживаемых версий и конфигураций, ошибок от IP из черного списка</title>", sep='', file=output)
        print("</head><body><h2>Удаление отчетов неподдерживаемых версий и конфигураций, ошибок от IP из черного списка. <br>Ошибки с комментариями не удаляются.</h2>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")

        cur = conn.cursor()
        cur.execute("select count(*) from issue")
        totalErrorsCount = cur.fetchone()[0]
        cur.close()

        stackIds = set()
        issueIds = set()
        errorsCount = 0
        reportsCount = 0
        for name in prefs.CONFIGS:
            sql = StringIO()
            print("select issueId, stackId from reportStack where configName='", name,"'", sep='', end='', file=sql)
            for ver in prefs.CONFIGS[name][0]:
                print(" and configVersion like '", ver,"%'", sep='', end='', file=sql)
            cur = conn.cursor()
            cur.execute(sql.getvalue())

            for r in cur.fetchall():
                issueIds.add(str(r[0]))
                stackIds.add(str(r[1]))
            cur.close()
            sql.close()

        # удаляем по блеклисту, не трогаем ошибки с комментариями
        if len(prefs.BLACKLIST) > 0:
            sql = StringIO()
            cur = conn.cursor()
            print("select reportStackId, file, issue.issueId from report innert join reportStack on reportStack.stackId=reportStackId inner join issue on issue.issueId=reportStack.issueId where issue.marked='' and (", sep='', end='', file=sql)
            start = True
            for ip in prefs.BLACKLIST:
                if start:
                    start = False
                else:
                    print(" or ", sep='', end='', file=sql)
                print("REMOTE_ADDR like '", ip,"%'", sep='', end='', file=sql)
            print(")", sep='', end='', file=sql)
            cur = conn.cursor()
            cur.execute(sql.getvalue())
            for r in cur.fetchall():
                if str(r[0]) in stackIds:
                    stackIds.remove(str(r[0]))
                if str(r[2]) in issueIds:
                    issueIds.remove(str(r[2]))
                if os.path.exists(prefs.DATA_PATH+"/"+r[1]):
                    os.remove(prefs.DATA_PATH+"/"+r[1])
                    reportsCount += 1
            cur.close()
            sql.close()

        cur = conn.cursor()
        cur.execute("select file from report where reportStackId not in ("+",".join(stackIds)+")")
        for r in cur.fetchall():
            if os.path.exists(prefs.DATA_PATH+"/"+r[0]):
                os.remove(prefs.DATA_PATH+"/"+r[0])
                reportsCount += 1
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from report where reportStackId not in ("+",".join(stackIds)+")")
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from reportStack where stackId not in ("+",".join(stackIds)+")")
        cur.close()

        # получить список стеков на которые ссылаются удаляемые репорты, но при этом есть ссылки на неудаляемые
        cur = conn.cursor()
        cur.execute("select reportStack.stackId from reportStack inner join report on reportStack.stackId=report.reportStackId where report.reportStackId not in (" + ",".join(stackIds) + ")")
        for r in cur.fetchall():
            stackIds.add(str(r[0]))
        cur.close()

        # получить список ошибок на которые ссылаются удаляемые репорты, но при этом есть ссылки на неудаляемые
        cur = conn.cursor()
        cur.execute("select issue.issueId from issue inner join reportStack on issue.issueId=reportStack.issueId where issue.issueId not in (" + ",".join(issueIds) + ")")
        for r in cur.fetchall():
            issueIds.add(str(r[0]))
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from issue where issueId not in (" + ",".join(issueIds) + ")")
        cur.close()

        conn.commit()
        conn.close()

        print("<H3>Удалено ошибок: ", totalErrorsCount-len(issueIds), ", отчетов: ", reportsCount, "</H3>", sep='', file=output)
        print("<hr><h3>Перейти:</h3><p><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></p>", sep='', file=output)
        print("</body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    url = environ['PATH_INFO'].split('/')
    secret = True if len(url) > 1 and url[1] == 's' else False
    if secret:          # все нижелащие url могут находится в зоне с ограниченным доступом, префикс может быть равен 's'
        s = url.pop(0)

    if secret and len(url) == 3 and url[1] == 'delete' and url[2].isdigit():
        output = StringIO()
        print('<!DOCTYPE html><html><head>', sep='', end='', file=output)
        print("<meta charset='utf-8'>", sep='', file=output)
        print("<link rel='stylesheet' href='", prefs.SITE_URL, "/style.css'>", sep='', file=output)
        print("<title>Удаление ошибки</title>", sep='', file=output)
        print("</head><body><h2>Удаление ошибки ", url[2], "</h2>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")

        stackIds = set()
        issueId = int(url[2])
        reportsCount = 0

        cur = conn.cursor()
        cur.execute("select stackId from reportStack where issueId=?", (issueId,))
        for r in cur.fetchall():
            stackIds.add(str(r[0]))
        cur.close()

        cur = conn.cursor()
        cur.execute("select file from report where reportStackId in ("+",".join(stackIds)+")")
        for r in cur.fetchall():
            if os.path.exists(prefs.DATA_PATH+"/"+r[0]):
                os.remove(prefs.DATA_PATH+"/"+r[0])
                reportsCount += 1
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from report where reportStackId in ("+",".join(stackIds)+")")
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from reportStack where issueId=?", (issueId,))
        cur.close()

        cur = conn.cursor()
        cur.execute("delete from issue where issueId=?", (issueId,))
        cur.close()

        conn.commit()
        conn.close()

        print("<H3>Удалено отчетов: ", reportsCount, "</H3>", sep='', file=output)
        print("<hr><h3>Перейти:</h3><p><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></p>", sep='', file=output)
        print("</body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    if len(url) in [2,3] and url[1] == 'errorsList' and (len(url) == 2 or url[2].isdigit()):
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
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
            SQLPacket = "select issue.issueId,errors,stackHash,configName,configVersion,extentions,marked,markedUser,markedTime,stackId from issue inner join reportStack where reportStack.issueId=issue.issueId order by issue.issueId desc,configName,configVersion,extentions"
        else:
            SQLPacket = "select issue.issueId,errors,stackHash,configName,configVersion,extentions,marked,markedUser,markedTime,stackId from issue inner join reportStack where reportStack.issueId=issue.issueId and configName='"+CONFIG_NAMES[int(url[2])]+"' order by issue.issueId desc,configName,configVersion,extentions"
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

        user = "" if 'REMOTE_USER' not in environ else environ['REMOTE_USER']
        SQLPacket = "update issue set marked='"+value+"', markedTime='"+datetime.datetime.now().strftime('%d.%m.%y %H:%M')+"', markedUser='"+user+"' where issueId="+url[2]
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
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css"/>
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Список отчетов сервиса регистрации ошибок 1С:Медицина</title>''', sep='', end='', file=output)
        print("</head><body><h2>Ошибка <span class='errorId'>", url[2], "</span></h2>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=OFF;")

        cur = conn.cursor()
        SQLPacket = "select issue.issueId,errors,stackHash,configName,configVersion,extentions,marked,markedUser,markedTime,stackId from issue inner join reportStack where reportStack.issueId=issue.issueId and issue.issueId=?"
        cur.execute(SQLPacket, (url[2],))
        stackId = prepareErrorTable(cur, output, secret, url[2])
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
        SQLPacket = "select * from report where reportStackId in ("+','.join(stackId)+") order by time desc"
        cur.execute(SQLPacket)
        found = False
        for r in cur.fetchall():
            print("<tr><td><span class='descTime'>", r[0], "</span></td><td>", r[1], "</td><td>", r[13], "</td><td>", r[2], "</td><td>",r[3],"</td><td>", r[4],"</td><td>",r[5],"</td><td>", r[6],"</td><td align='center'>",r[10],"</td><td>","" if r[12] is None else r[12],"</td><td align='center'>","<a href='",prefs.SITE_URL,"/s" if secret else "","/report/",r[9],"'>",'Файл/скрин ('+str(r[8])+')' if r[14]==1 else r[8],"</a></td></tr>", sep='', file=output)
            found = True

        cur.close()
        conn.close()
        print("</table>", sep='', file=output)

        print('''<p><a href='https://its.1c.ru/db/v8320doc#bookmark:dev:TI000002262'>Документация на ИТС по отчету об ошибке</a></p>
<p><a href="''', prefs.SITE_URL, "/s" if secret else "", '''/errorsList">Список ошибок</a></p>''', sep='', file=output)
        print("</body></html>", sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if len(url) == 3 and url[1] == 'report' and os.path.exists(prefs.DATA_PATH+"/"+url[2]):
       # отчет в открытой и закрытой зонах
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


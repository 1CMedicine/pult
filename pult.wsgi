# -*- coding: utf-8 -*-
import os
import os.path
import sys
import uuid
import tempfile, shutil
import zipfile
import sqlite3
import unicodedata
import string
from io import StringIO
import json
from json2html import *
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from threading import Thread
import datetime
import re
import whois
from ipwhois import IPWhois

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
        part = stream.read(min(length, 1024*1024*10)) # 10MB buffer size
        if not part: break
        body.write(part)
        length -= len(part)
    body.seek(0)
    environ['wsgi.input'] = body
    return body


def array2str(arrs, sql):
    sql2 = StringIO()
    sql2.write("[")
    for line in arrs:
        if type(line) == list:
            if len(line)>0:
                array2str(line, sql2)
        elif len(line.strip())>0:
            if sql2.tell() > 1:
                sql2.write(',')
            sql2.write('"') 
            sql2.write(line.strip().replace(">", "&#62;").replace("<", "&#60;").replace("\"", "&#34;").replace('\n', "<br>").replace('\t', "&#9;").replace("'", "&apos;").replace('\\', "&#92;"))
            sql2.write('"')
    sql2.write("]")
    if sql2.tell() != 2:        # '[]' - empty array
        if sql.tell() > 1:
            sql.write(',')
        sql.write(sql2.getvalue())


def prepareErrorTableLine(r, output, secret, issueN):
    print("<tr", sep='', end='', file=output)
    if len(r[5]) != 0 and r[10] is not None:
        print(" class='marked original_conf'", sep='', end='', file=output)
    elif len(r[5]) != 0:
        print(" class='marked'", sep='', end='', file=output)
    elif r[10] is not None:
        print(" class='original_conf'", sep='', end='', file=output)
    print(">", sep='', end='', file=output)
    if issueN == 0:
        print("<td align='center'><span class='errorId'><a href='", prefs.SITE_URL, "/s" if secret else "", "/reports/",str(r[0]),"'>",str(r[0]).zfill(5),"</a></span><br><span class='descTime'>",r[9],"</span></td>", sep='', file=output)

    errors_txt = r[1]+"<br><br>"
    try:
        errors_json = json.loads(r[1])
        errors_txt = json2html.convert(json=errors_json, escape=0)
    except:
        erros_txt = r[1]

    print("<td style='word-wrap: break-word'>",errors_txt,"</td>",  file=output)
    print("<td style='word-wrap: break-word;vertical-align: top;'>","<br>".join(r[2]),"</td>", sep='',  file=output)
    txt = r[5].replace("'","&amp;")
    if secret:
        print("<td align='center'><input type='text' size='10' id='line",str(r[0]), "' title='", txt ,"' value='", txt, "' onchange='mark(\"line",str(r[0]),"\")'/>", sep='', file=output)
        print("<br><small><a href='", prefs.SITE_URL,"/s/delete/",str(r[0]), "' ",'''onclick='return confirm("Вы уверены?")'>удалить</a></small>''', sep='', file=output)
    else:
        print("<td align='center'><input type='text' size='10' id='line",str(r[0]), "' title='", txt ,"' disabled value='", txt, "'/>", sep='', file=output)
    print("<span class='descTime'><br>", r[6], "<br>", r[7], "</span>", sep='', file=output)
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
        conf = r[2]+", "+r[3]
        id = str(r[8])
        stackId.append(id)
        if len(r[4]) > 0 and issueN != 0:
            ext_json = json.loads(r[4])
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
            pr[2] = {conf: 1}
        else:
            pr[2][conf] = 1

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


def whois_cache(conn, environ):
    cur = conn.cursor()
    cur.execute("select time from whois where ip=?", (environ['REMOTE_ADDR'],))
    whois_name = cur.fetchone()
    cur.close()

    if whois_name is not None:
        year = datetime.datetime.now().strftime('%y')
        if whois_name[0][6:8] != year:
            cur = conn.cursor()
            cur.execute("delete from whois where ip=?", (environ['REMOTE_ADDR'],))
            cur.close()
            conn.commit()
            print("clear whois cache:", environ['REMOTE_ADDR'], whois_name[0], sep=' ', end='', file=environ["wsgi.errors"])
            whois_name = None

    if whois_name is None:
        name = None
        try:
            name = whois.whois(environ['REMOTE_ADDR'])
        except Exception as e:
            print('ERROR: whois(', environ['REMOTE_ADDR'], ') ', str(e), sep=' ', end='', file=environ["wsgi.errors"])
            pass

        if name is not None and (name.domain_name is not None or name.org is not None):
            cur = conn.cursor()
            cur.execute("insert into whois values (?,?,?,?)", (environ['REMOTE_ADDR'], name.domain_name, name.org, datetime.datetime.now().strftime('%d.%m.%y %H:%M')))
            cur.close()
            conn.commit()
        else:
            try:
                obj = IPWhois(environ['REMOTE_ADDR'])
                res = obj.lookup_whois()
            except Exception as e:
                print('ERROR: IPWhois(', environ['REMOTE_ADDR'], ') ', str(e), sep=' ', end='', file=environ["wsgi.errors"])
                pass

            if res is not None:
                cur = conn.cursor()
                cur.execute("insert into whois values (?,?,?,?)", (environ['REMOTE_ADDR'], res['asn_cidr'], res['asn_description'], datetime.datetime.now().strftime('%d.%m.%y %H:%M')))
                cur.close()
                conn.commit()


def insertReport(conn, report, stackId, fn, environ, issue, changeEnabled):
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
        1 if 'additionalFiles' in report or  'additionalData' in report else 0,
        report['errorInfo']['applicationErrorInfo']['stackHash'],
        1 if 'screenshot' in report and report['screenshot'] is not None else 0)

    cur = conn.cursor()
    cur.execute("insert into report values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", i)
    cur.close()

    if not report['configInfo']['changeEnabled'] and changeEnabled != 0:
        cur = conn.cursor()
        cur.execute("update issue set changeEnabled=0 where issueId=(?)", (issue,))
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

        if len(errors) > 1 and errors[1][0].startswith('Превышен максимальный расход памяти сервера за один вызов'):
            print("p4:", str(errors[1]), file=environ["wsgi.errors"])
            return True

        if len(errors) > 1 and errors[-1][0].startswith('Внутренняя ошибка'):
            print("p5:", str(errors[-1]), file=environ["wsgi.errors"])
            return True
    except:
        print(str(errors), file=environ["wsgi.errors"])
        raise

    return False


def errorInConf(errors, stack, environ):
    try:
        if errors[0][0].startswith('{ВнешняяОбработка.') or errors[0][0].startswith('{ВнешнийОтчет.'):
            print("e1:", errors[0][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('{ВнешняяОбработка.') or errors[-1][0].startswith('{ВнешнийОтчет.'):
            print("e4:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[0][0].find('Неизвестный модуль') != -1:
            print("e5:", errors[0][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Ошибка при выполнении файловой операции'):
            print("e6:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Конфликт блокировок при выполнении транзакции'):
            print("e7:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Ошибка блокировки объекта'):
            print("e8:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Ошибка совместного доступа к файлу'):
            print("e9:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[0][0].startswith('{Справочник.ВерсииРасширений.'):
            print("e10:", errors[0][0], file=environ["wsgi.errors"])
            return False

        if errors[0][0].startswith('{mngbase'):
            print("e11:", errors[0][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Не удалось заблокировать таблицу'):
            print("e12:", errors[-1][0], file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Недостаточно прав') or errors[-1][0].startswith('Нарушение прав доступа') or (len(errors[-1][1]) > 0 and errors[-1][1][0] == "AccessViolation"):
            print("r1:", str(errors[-1]), file=environ["wsgi.errors"])
            return False

        if errors[-1][0].startswith('Ошибка доступа к файлу'):
            print("r2:", str(errors[-1]), file=environ["wsgi.errors"])
            return False

        if len(errors[0][1]) > 0 and errors[0][1][-1] == "ExceptionRaisedFromScript":
            print("u1:", str(errors[0]), file=environ["wsgi.errors"])
            return False

        if len(errors[-1][1]) > 0 and errors[-1][1][-1] == "ScriptCompileError":
            print("c1:", str(errors[-1]), file=environ["wsgi.errors"])
            return False

        for e1 in errors:
            e = e1[0]
            dot = e.find('.')
            if dot != -1:
                space = e.find(' ', 2, dot)
                if space != -1 and not e.startswith('{E'):    # расширение, но не патч
                    print("e2:", e, file=environ["wsgi.errors"])
                    return False

                if e.find('_', dot+1) != -1:    # в имени объекта метаданных в тч в тексте ошибки есть подчеркивание, значит объект нетиповой или в тексте ошибки есть упоминание нетипового объекта
                    print("e3:", e, file=environ["wsgi.errors"])
                    return False

    except:
        print(str(errors), file=environ["wsgi.errors"])
        raise

    # Вызов из объекта пользователя
    try:
        for s1 in stack:
            s = s1[0]
            dot = s.find('.')
            if dot != -1:
                space = s.find(' ', 1, dot)
                if space != -1 and not s.startswith('E'):   #расширение, но не патч
                    print("s5:", s, file=environ["wsgi.errors"])
                    return False

                pod = s.find('_', dot+1)
                if pod != -1 and not(len(s) > pod+11 and s[pod:pod+11] == "__ОТЛАДКА__"):    # в имени объекта метаданных есть подчеркивание, значит объект нетиповой, но в модуле __ОТЛАДКА__ ловим ошибку
                    print("s6:", s, file=environ["wsgi.errors"])
                    return False

            if s.startswith('ВнешняяОбработка.') or s.startswith('ВнешнийОтчет.') or s.startswith('Справочник.ДополнительныеОтчетыИОбработки.') or s.startswith('ОбщийМодуль.ДополнительныеОтчетыИОбработки.'):
                print("s4:", s, file=environ["wsgi.errors"])
                return False

            if s1[-1].find('ВнешняяОбработка') != -1 or s1[-1].find('ВнешнийОбъект') != -1:
                print("s7:", s1[-1], file=environ["wsgi.errors"])
                return False

    except:
        print(str(stack), file=environ["wsgi.errors"])
        raise

    return True


def clear(conn, output, delete):
    if not delete:
        cur = conn.cursor()
        cur.execute("select count(*) from issue")
        totalErrorsCount = cur.fetchone()[0]
        cur.close()

        print("<p>Ошибок в базе - ", str(totalErrorsCount), "</p>", sep='', end='', file=output)

        cur = conn.cursor()
        cur.execute("select count(*) from report")
        totalReportsCount = cur.fetchone()[0]
        cur.close()

        print("<p>Отчетов в базе - ", str(totalReportsCount), "</p>", sep='', end='', file=output)

    # выбираем все отчеты и ошибки, которые надо оставить по критерию - конфа/версия
    stackIds = set()
    issueIds = set()
    reportsCount = 0
    for name in prefs.CONFIGS:
        sql = StringIO()
        start = True
        print("select issueId, stackId from reportStack where configName='", name,"' and (", sep='', end='', file=sql)
        for ver in prefs.CONFIGS[name][0]:
            if not start:
                print(" or", sep='', end='', file=sql)
            else:
                start = False
            print(" configVersion like '", ver,"%'", sep='', end='', file=sql)
        print(")", sep='', end='', file=sql)
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
        if not delete:
            print("<p>Удаляются отчеты от хостов из блеклиста:</p><ol>", file=output)
        for r in cur.fetchall():
            if str(r[0]) in stackIds:
                stackIds.remove(str(r[0]))
            if str(r[2]) in issueIds:
                issueIds.remove(str(r[2]))
            if len(r[1]) > 0 and os.path.exists(prefs.DATA_PATH+"/"+r[1]):
                if delete:
                    os.remove(prefs.DATA_PATH+"/"+r[1])
                elif not delete:
                    print("<li>"+prefs.DATA_PATH+"/"+r[1]+"</li>", file=output)
                reportsCount += 1
        if not delete:
            print("</ol>", file=output)
        cur.close()
        sql.close()

    # удаляем все отчеты, которые не соотвествуют критерию - конфа/версия
    cur = conn.cursor()
    cur.execute("select file from report where reportStackId not in ("+",".join(stackIds)+")")
    if not delete:
        print("<p>Удаляются отчеты неподдерживаемых конфигураций и версий:</p><ol>", file=output)
    for r in cur.fetchall():
        if len(r[0]) > 0 and os.path.exists(prefs.DATA_PATH+"/"+r[0]):
            if delete:
                os.remove(prefs.DATA_PATH+"/"+r[0])
            elif not delete:
                print("<li>"+prefs.DATA_PATH+"/"+r[0]+"</li>", file=output)
            reportsCount += 1
    if not delete:
        print("</ol>", file=output)
    cur.close()

    if delete:
        # удаляем все отчеты, которые не соотвествуют критерию - конфа/версия
        cur = conn.cursor()
        cur.execute("delete from report where reportStackId not in ("+",".join(stackIds)+")")
        cur.close()

        # удаляем все стеки, которые не соотвествуют критерию - конфа/версия
        cur = conn.cursor()
        cur.execute("delete from reportStack where stackId not in ("+",".join(stackIds)+")")
        cur.close()

    # получить список ошибок на которые ссылаются удаляемые репорты, но при этом есть ссылки на неудаляемые
    cur = conn.cursor()
    cur.execute("select reportStack.issueId from reportStack inner join report on reportStack.stackId=report.reportStackId where report.reportStackId in (" + ",".join(stackIds) + ")")
    for r in cur.fetchall():
        issueIds.add(str(r[0]))
    cur.close()

    if delete:
        cur = conn.cursor()
        cur.execute("delete from issue where issueId not in (" + ",".join(issueIds) + ")")
        cur.close()
    else:
        cur = conn.cursor()
        cur.execute("select issueId from issue where issueId not in (" + ",".join(issueIds) + ")")
        print("<p>Удаляются ошибки:</p>", file=output)
        errorsCount = 0
        for r in cur.fetchall():
            print("<a href='", prefs.SITE_URL, "/s/reports/",str(r[0]),"'>",str(r[0]).zfill(5),"</a><br>", sep='', file=output)
            errorsCount += 1
        cur.close()
        print("</ol>", file=output)
        print("<p>Удаляется ошибок: ", errorsCount, ", отчетов: ", reportsCount, "</p>", sep='', file=output)
        print("<p>Остается ошибок: ", len(issueIds), ", отчетов: ", str(totalReportsCount-reportsCount), "</p>", sep='', file=output)

        conn.commit()


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
    background-color: rgb(190,255,255) !important;
}
.original_conf {
    background-color: rgb(255,135,135);
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
.summary {
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
function selectNetwork(network) {
    if (network != '')
        document.location.href="''', prefs.SITE_URL, '''/s/errorsList/"+network.replace(/\//g, "&frasl;")
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
                    needSendReport = True

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

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")
        needStoreReport = False
        if 'configInfo' in report and report['configInfo']['name'] in prefs.CONFIGS:

            try:
                cur = conn.cursor()
                cur.execute("select count(*) from clients where clientID=? and configName=? and configVersion=?", (report['clientInfo']['systemInfo']['clientID'], report['configInfo']['name'], report['configInfo']['version']))
                cnt = cur.fetchone()[0]
                cur.close()

                if cnt == 0:
                    cur = conn.cursor()
                    cur.execute("insert into clients values (?,?,?,?)", (report['clientInfo']['systemInfo']['clientID'], report['configInfo']['name'], report['configInfo']['version'], environ['REMOTE_ADDR']))
                    cur.close()
                    conn.commit()
                    if prefs.USE_WHOIS:
                        whois_cache(conn, environ)

            except Exception as e:
                print(repr(e), file=environ["wsgi.errors"])
                raise

            for ver in prefs.CONFIGS[report['configInfo']['name']][0]:
                if ver == report['configInfo']['version'][:len(ver)]:
                    needStoreReport = True
                    break

        if needStoreReport:
            #  Если IP не в стоплисте и нет стека, ошибки или информации и конфе или ошибка во внешних объектах, то игнорируем отчет, так как нам интересны только ошибки модулей нашей конфы
            full_data = ('stackHash' in report['errorInfo']['applicationErrorInfo'] and 'errors' in report['errorInfo']['applicationErrorInfo'] and 'configInfo' in report)
            in_stop = inStopLists(environ)
            in_conf = None
            platform = None
            if full_data and not in_stop:
                in_conf = not prefs.ONLY_IN_CONF or errorInConf(report['errorInfo']['applicationErrorInfo']['errors'], report['errorInfo']['applicationErrorInfo']['stack'], environ)
                if in_conf:
                    platform = platformError(report['errorInfo']['applicationErrorInfo']['errors'], environ)
            if full_data and not in_stop and in_conf and not platform:
                prev_issue = None
                te = StringIO()
                array2str(report['errorInfo']['applicationErrorInfo']['errors'], te)

                # схлапываем те строки, которые размножают одну ошибку в отчетах
                errors = re.sub(r"&apos;file://.*?&apos;", r"file://[path]", te.getvalue())

                # убираем непечатные символы, русский берем из http://www.fileformat.info/info/unicode/category/index.htm
                errors = u''.join([c for c in errors if unicodedata.category(c) in ('Lu', 'Ll') or c in string.printable])

                cur = conn.cursor()
                cur.execute("select issueId, changeEnabled from issue where errors=?", (errors,))
                issue = cur.fetchone()
                cur.close()

                fn = str(uuid.uuid4())+".zip"
                needSendMail = False
                needStoreReport = False
                time = report['time'][:10]
                if prefs.USE_WHOIS:
                    whois_cache(conn, environ)
                if issue is None:
                    cur = conn.cursor()
                    cur.execute("insert into issue (errors, time) values (?,?)", (errors, time))
                    cur.close()

                    cur = conn.cursor()
                    cur.execute("select issueId, changeEnabled from issue where errors=?", (errors,))
                    row = cur.fetchone()
                    issue = row[0]
                    changeEnabled = row[1]
                    cur.close()

                    stack = insertReportStack(conn, report, issue)
                    insertReport(conn, report, stack, fn, environ, issue, changeEnabled)
                    needStoreReport = True

                    if len(prefs.SMTP_HOST) > 0 and len(prefs.SMTP_FROM) > 0 and len(prefs.CONFIGS[report['configInfo']['name']][1]) > 0:
                        cur = conn.cursor()
                        cur.execute("insert into smtpQueue values (?)", (issue,))
                        needSendMail = True
                        cur.close()
                else:
                    changeEnabled = issue[1]
                    issue = issue[0]

                    cur = conn.cursor()
                    cur.execute("update issue set time=? where issueId=?", (time, issue))
                    cur.close()

                    prev_reports = None
                    if 'systemInfo' in report['clientInfo'] and 'additionalFiles' not in report and 'additionalData' not in report:
                        i = (issue, report['clientInfo']['systemInfo']['clientID'], report['configInfo']['name'], report['configInfo']['version'])
                        prev_reports = None
                        if 'screenshot' in report and report['screenshot'] is not None:
                            cur = conn.cursor()
                            # в запросе не учитываем записи с пустыми отчетами (удаленные из файловой системы по ошибке). Такие записи оставляем для истории
                            cur.execute("select report.rowid, report.count, report.userDescription from report inner join reportStack on reportStackId=stackId where hasScreenshot=1 and file!='' and issueId=? and clientID=? and configName=? and configVersion=?", i)
                            prev_reports = cur.fetchone()
                            cur.close()
                        else:
                            cur = conn.cursor()
                            # в запросе не учитываем записи с пустыми отчетами (удаленные из файловой системы по ошибке). Такие записи оставляем для истории
                            cur.execute("select report.rowid, report.count, report.userDescription from report inner join reportStack on reportStackId=stackId where file!='' and issueId=? and clientID=? and configName=? and configVersion=?", i)
                            prev_reports = cur.fetchone()
                            cur.close()

                        if prev_reports is not None:
                            descTime = report['time'][0:10]+" "+report['time'][11:]
                            if prev_reports[2] is not None and 'userDescription' in report['errorInfo'] and report['errorInfo']['userDescription'] != '':
                                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                                SQLPacket += prev_reports[2] +"<br><span class=\"descTime\">"+descTime+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>'"
                            elif prev_reports[2] is None and 'userDescription' in report['errorInfo'] and report['errorInfo']['userDescription'] != '':
                                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", time='"+report['time']+"', userDescription='"
                                SQLPacket += "<span class=\"descTime\">"+descTime+"</span>&nbsp;<span class=\"desc\">"+report['errorInfo']['userDescription']+"</span>'"
                            elif prev_reports[2] is not None: 
                                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", userDescription='"+prev_reports[2] +"<br><span class=\"descTime\">"+descTime+"</span>'"
                            else:
                                SQLPacket = "update report set count="+str(prev_reports[1]+1)+", userDescription='<span class=\"descTime\">"+descTime+"</span>'"
                            SQLPacket += " where rowid="+str(prev_reports[0])

                            cur = conn.cursor()
                            cur.execute(SQLPacket)
                            cur.close()
                        else:
                            stack = insertReportStack(conn, report, issue)
                            insertReport(conn, report, stack, fn, environ, issue, changeEnabled)
                            needStoreReport = True
                    else:
                        stack = insertReportStack(conn, report, issue)
                        insertReport(conn, report, stack, fn, environ, issue, changeEnabled)
                        needStoreReport = True

                conn.commit()
                if needSendMail:
                    Thread(target=send_mail, args=()).start()

                if needStoreReport:
                    shutil.copy(fzip.name, prefs.DATA_PATH+"/"+fn)

            else:
                t = StringIO()
                print("report filtered: stopList - ", in_stop, ", full_data - ", full_data, ", in_conf - ", in_conf, ", platform - ", platform, sep='', end='', file=environ["wsgi.errors"])

        conn.close()
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


    if environ['PATH_INFO'] == '/s/clients':
        output = StringIO()
        print('<!DOCTYPE html><html><head>', sep='', end='', file=output)
        print("<meta charset='utf-8'>", sep='', file=output)
        print("<link rel='stylesheet' href='", prefs.SITE_URL, "/style.css'>", sep='', file=output)
        print("<title>Пользователи конфигураций</title>", sep='', file=output)
        print("</head><body><h2>Пользователи конфигураций, отправившие отчеты об ошибках</h2>", sep='', file=output)

        arms = 0
        clients = 0
        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")
        cur = conn.cursor()
        cur.execute("select name, org, configName, configVersion, count(clientID),min(REMOTE_ADDR) from clients left join whois on ip=REMOTE_ADDR group by configName, configVersion, name, org")
        print("<table style='width: 100%; table-layout : fixed;' border=1><th style='width: 10%'>FQDN или сеть</th><th style='width: 70%'>Описание</th><th style='width: 10%'>Конфигурация</th><th style='width: 10%'>Версия</th><th style='width: 5%'>АРМов</th>", sep='', file=output)
        for r in cur.fetchall():
            print("<tr><td>",r[0] if r[0] is not None else r[5],"</td><td>",r[1] if r[1] is not None else "","</td><td>",r[2],"</td><td align='center'>",r[3],"</td><td align='center'>",r[4],"</td></tr>", sep='', file=output)
            clients += 1
            arms += r[4]
        cur.close()
        print("</table>", file=output)
        conn.close()

        print('<p>Клиентов (сетей) - ', clients, sep='', end='<br>', file=output)
        print('АРМов - ', arms, sep='', file=output)

        print("<hr><h3>Перейти:</h3><p><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></p>", sep='', file=output)
        print("</body></html>", sep='', end='', file=output)

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
        clear(conn, output, False)
        print("<H2><a href='", prefs.SITE_URL,"/s/clear_ok' ",'''onclick='return confirm("Вы уверены?")'>Удалить</a></H2>''', sep='', file=output)
        conn.close()

        print("<hr><h3>Перейти:</h3><p><a href='", prefs.SITE_URL, "/s/errorsList'>Список ошибок</a></p>", sep='', file=output)
        print("</body></html>", sep='', end='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]

    if environ['PATH_INFO'] == '/s/clear_ok':
        output = StringIO()
        print('<!DOCTYPE html><html><head>', sep='', end='', file=output)
        print("<meta charset='utf-8'>", sep='', file=output)
        print("<link rel='stylesheet' href='", prefs.SITE_URL, "/style.css'>", sep='', file=output)
        print("<title>Удаление отчетов неподдерживаемых версий и конфигураций, ошибок от IP из черного списка</title>", sep='', file=output)
        print("</head><body><h2>Удалено</h2>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=ON;")
        clear(conn, output, True)
        conn.commit()
        conn.execute("VACUUM")
        conn.close()

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
            if len(r[0]) != 0 and os.path.exists(prefs.DATA_PATH+"/"+r[0]):
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

    try:
        url2_is_d = url[2].isdigit()
        network = url[2].replace("&frasl;", "/")
        conf_number = int(url[2])
    except:
        pass
    if len(url) > 1 and url[1] == 'errorsList' and (len(url) == 2 or (len(url) == 3 and not url2_is_d) or (len(url) == 3 and url2_is_d and conf_number < len(CONFIG_NAMES))):
        output = StringIO()
        print('''<!DOCTYPE html><html><head>
<meta charset='utf-8'>
<link rel='stylesheet' href="''', prefs.SITE_URL, '''/style.css"/>
<script src="''', prefs.SITE_URL, '''/tables.js"></script>
<title>Список ошибок сервиса регистрации ошибок 1С:Медицина</title>
</head><body><H2>Список ошибок сервиса регистрации ошибок</H2>
<p><small><span class='original_conf'>Красный фон</span> - без метки и конфигурация клиента на полной поддержке<br>
<span class='marked'>Бирюзовый фон</span> - есть отметка<br>
Ошибки отсортированы в порядке получения последнего отчета (выше - воспроизвели позднее). См. дату под номером ошибки</small></p>
''', sep='', file=output)

        if secret:
            print("<p>Фильтры на: конфигурацию - <select name='configName' size='1' onchange='selectConfig(this.value)'>", sep='', file=output)

            if len(url) == 2 or len(url) == 3 and not url2_is_d:
                print("<option value='sn' selected/>", sep='', file=output)
            else:
                print("<option value='sn'/>", sep='', file=output)
            if len(url) == 3 and url2_is_d:
                for i in range(len(CONFIG_NAMES)):
                    if i == conf_number:
                        print("<option value='s", i, "' selected>", CONFIG_NAMES[i], "</option>", sep='', file=output)
                    else:
                        print("<option value='s", i, "'>", CONFIG_NAMES[i], "</option>", sep='', file=output)
            else:
                for i in range(len(CONFIG_NAMES)):
                    print("<option value='s", i, "'>", CONFIG_NAMES[i], "</option>", sep='', file=output)
            print("</select> &nbsp;&nbsp;&nbsp;", sep='', file=output)
            if len(url) == 3 and not url2_is_d:
                print("клиентский FQDN/сеть - <input id='network' autocomplete='on' type='text' size='30' name='network' value='", network, "'onchange='selectNetwork(this.value)'/></p>", sep='', file=output)
            else:
                print("клиентский FQDN/сеть - <input id='network' autocomplete='on' type='text' size='30' name='network' onchange='selectNetwork(this.value)'/></p>", sep='', file=output)

        conn = sqlite3.connect(prefs.DATA_PATH+"/reports.db")
        conn.execute("PRAGMA foreign_keys=OFF;")
        cur = conn.cursor()
        if len(url) == 2:
            SQLPacket = """select issue.issueId,errors,configName,configVersion,extentions,marked,markedUser,markedTime,stackId,issue.time,changeEnabled 
		from issue 
		inner join reportStack on reportStack.issueId=issue.issueId 
		order by issue.time desc, issue.issueId desc"""
        elif url2_is_d:
            SQLPacket = f"""select issue.issueId,errors,configName,configVersion,extentions,marked,markedUser,markedTime,stackId,issue.time,issue.changeEnabled 
		from issue 
		inner join reportStack on reportStack.issueId=issue.issueId 
		where issue.issueId in (select distinct issueId from reportStack where configName='{CONFIG_NAMES[conf_number]}') 
		order by issue.time desc, issue.issueId desc"""
        else:
            SQLPacket = f"""select issue.issueId,errors,configName,configVersion,extentions,marked,markedUser,markedTime,stackId,issue.time,issue.changeEnabled 
		from issue 
		inner join reportStack on reportStack.issueId=issue.issueId where issue.issueId in 
		    (select distinct issueId from report inner join whois on REMOTE_ADDR=ip inner join reportStack on reportStack.stackId=report.reportStackId where whois.name='{network}') 
		order by issue.time desc, issue.issueId desc"""
        cur = conn.cursor()
        cur.execute(SQLPacket)
        prepareErrorTable(cur, output, secret)
        cur.close()
        conn.close()

        print('''<p><a href='https://its.1c.ru/db/v8320doc#bookmark:dev:TI000002262'>Документация на ИТС по отчету об ошибке</a></br>
<a href="''', prefs.SITE_URL, '''/s/clients">Список пользователей конфигураций</a></br>
<a href="''', prefs.SITE_URL, '''/s/settings">Настройки сервиса</a></p>
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
        SQLPacket = "select issue.issueId,errors,configName,configVersion,extentions,marked,markedUser,markedTime,stackId,issue.time,issue.changeEnabled from issue inner join reportStack where reportStack.issueId=issue.issueId and issue.issueId=?"
        cur.execute(SQLPacket, (url[2],))
        stackId = prepareErrorTable(cur, output, secret, url[2])
        cur.close()

        print('''<h3>Отчеты</h3><table width='100%' border=1><tr>
<th>Дата</th>
<th>Хеш стека/ID клиента</th>
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
        SQLPacket = "select report.*, whois.name, whois.org from report left join whois on REMOTE_ADDR=whois.ip where reportStackId in ("+','.join(stackId)+") order by time desc"
        cur.execute(SQLPacket)
        found = False
        for r in cur.fetchall():
            ip_name = r[13]
            if r[17] is not None: 
                ip_name += "<br><a href='http://"+r[17]+"'>" + r[17]+"</a>"
            if r[18] is not None: 
                ip_name += "<br>" + r[18]
            print("<tr><td><span class='descTime'>", r[0][0:10]," ",r[0][11:], "</span></td><td>", r[15],"<br>", r[7], "</td><td>", ip_name, "</td><td>", r[2], "</td><td>",r[3],"</td><td>", r[4],"</td><td>",r[5],"</td><td>", r[6],"</td><td align='center'>",r[10],"</td><td>","" if r[12] is None else r[12],"</td>", sep='', file=output)
            print("<td align='center'>", sep='', file=output)
            if r[9] != "":
                print("<a href='",prefs.SITE_URL,"/s" if secret else "","/report/",r[9],"'>", sep='', file=output)
                if r[14] == 1 and r[16] == 1:
                    print('Файл/Скрин ('+str(r[8])+')', sep='', file=output)
                elif r[14] == 1:
                    print('Файл ('+str(r[8])+')', sep='', file=output)
                elif r[16] == 1:
                    print('Скрин ('+str(r[8])+')', sep='', file=output)
                else:
                    print(str(r[8]), sep='', file=output)
                print("</a>", sep='', file=output)
            else:        # было удаление отчета из файловой системы
                print('Был удален :(<br>Ждите новый', sep='', file=output)
            print("</td></tr>", sep='', file=output)
            found = True

        cur.close()
        conn.close()
        print("</table>", sep='', file=output)

        print('''<p><a href='https://its.1c.ru/db/v8320doc#bookmark:dev:TI000002262'>Документация на ИТС по отчету об ошибке</a><br>
<a href="''', prefs.SITE_URL, '''/s/clients">Список пользователей конфигураций</a></br>
<a href="''', prefs.SITE_URL, "/s" if secret else "", '''/errorsList">Список ошибок</a></p>''', sep='', file=output)
        print("</body></html>", sep='', file=output)

        ret = output.getvalue().encode('UTF-8')
        start_response('200 OK', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(ret)))
        ])
        return [ret]


    if len(url) == 3 and url[1] == 'report' and ".." not in url[2] and os.path.exists(prefs.DATA_PATH+"/"+url[2]):
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


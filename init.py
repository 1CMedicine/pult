#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Инициализация сервиса
# Папка prefs.DATA_PATH должна иметь владельца пользователя и группу апача
# После создания базы reports.db этому файлу надо установить владельца - пользователя и группу апача

import sqlite3
import os
import pwd
import grp
import os.path
import sys

local_path = os.path.split(__file__)[0]
if local_path not in sys.path:
    sys.path.insert(0, local_path)

import prefs

conn = sqlite3.connect(prefs.DATA_PATH+'/reports.db')
conn.execute("PRAGMA foreign_keys=ON;")
cur = conn.cursor()

cur.execute("""create table if not exists issue (
    issueId INTEGER PRIMARY KEY,
    errors TEXT NOT NULL,
    marked TEXT NOT NULL DEFAULT '',
    markedUser TEXT NOT NULL DEFAULT '',
    markedTime TEXT NOT NULL DEFAULT '',
    time TEXT NOT NULL,
    changeEnabled BOOLEAN NULL CHECK (changeEnabled IN (0)),
    cnt INTEGER NOT NULL DEFAULT 1,
    UNIQUE(errors)
);""")


cur.execute("""create table if not exists reportStack (
    stackId INTEGER PRIMARY KEY,
    issueId INTEGER NOT NULL,
    configName TEXT NOT NULL,
    configVersion TEXT NOT NULL,
    extentions TEXT NOT NULL,
    UNIQUE(issueId, configName, configVersion, extentions),
    FOREIGN KEY(issueId) REFERENCES issue(issueId)
);""")

cur.execute("""create table if not exists report (
    time TEXT NOT NULL,
    userName TEXT NOT NULL,
    appVersion TEXT NOT NULL,
    clientPlatformType TEXT NOT NULL,
    serverPlatformType TEXT NOT NULL,
    dataSeparation TEXT NOT NULL,
    dbms TEXT NOT NULL,
    clientID TEXT NOT NULL,
    count INTEGER NOT NULL,
    file TEXT NOT NULL,
    changeEnabled BOOLEAN NOT NULL CHECK (changeEnabled IN (0, 1)),
    reportStackId INTEGER NOT NULL,
    userDescription TEXT NULL,
    REMOTE_ADDR TEXT NOT NULL,
    hasFiles BOOLEAN NOT NULL CHECK (hasFiles IN (0, 1)),
    stackHash TEXT NOT NULL,
    hasScreenshot BOOLEAN NOT NULL CHECK (hasScreenshot IN (0, 1)),
    FOREIGN KEY(reportStackId) REFERENCES reportStack(stackId)
);""")

cur.execute("""create table if not exists smtpQueue (
    issueId INTEGER PRIMARY KEY,
    FOREIGN KEY(issueId) REFERENCES issue(issueId) ON DELETE CASCADE
);""")

cur.execute("""create table if not exists whois (
    ip TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    org TEXT,
    time TEXT NOT NULL,
    UNIQUE(ip)
);""")

cur.execute("""create table if not exists clients (
    clientID TEXT NOT NULL,
    configName TEXT NOT NULL,
    configVersion TEXT NOT NULL,
    REMOTE_ADDR TEXT NOT NULL,
    UNIQUE(clientID, configName, configVersion)
);""")

cur.execute("CREATE INDEX IF NOT EXISTS report_reportstack_index ON report (reportStackId);")
cur.execute("CREATE INDEX IF NOT EXISTS reportStack_issue_index ON reportStack (issueId);")
conn.commit()

uid = pwd.getpwnam(prefs.APACHE_USER).pw_uid
gid = grp.getgrnam(prefs.APACHE_GROUP).gr_gid
os.chown(prefs.DATA_PATH+"/reports.db", uid, gid)

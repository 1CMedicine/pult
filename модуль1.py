from io import StringIO
import json

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



json_string ='''		[		[
					"{ОбщийМодуль.ДинПолеОтображениеМД.Модуль(485)}: Ошибка при вызове метода контекста (Напечатать)",
					[
						"ScriptRuntimeError"
					],
					"",
					""
				],
				[
					"",
					[],
					"",
					""
				],
				[
					"Ошибка при получении характеристик принтера",
					[],
					"",
					""
				],
				[
					"Ошибка при получении характеристик принтера",
					[
						"PrinterError"
					],
					"",
					""
				]
			]'''

data = json.loads(json_string)
sql = StringIO()
array2str(data, sql)

print(sql.getvalue())
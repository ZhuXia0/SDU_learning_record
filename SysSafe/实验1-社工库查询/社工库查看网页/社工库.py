import pyodbc
import pandas as pd


def inspect_database(server, database, username, password):
    try:
        # 设置Pandas显示选项
        pd.set_option('display.max_columns', None)  # 显示所有列
        pd.set_option('display.max_rows', None)  # 显示所有行
        pd.set_option('display.max_colwidth', None)  # 显示完整列内容
        pd.set_option('display.width', None)  # 自动调整宽度

        conn = pyodbc.connect(
            f"Driver={{ODBC Driver 18 for SQL Server}};"
            f"Server={server};"
            f"Database={database};"
            f"UID={username};"
            f"PWD={password};"
            f"Encrypt=yes;"
            f"TrustServerCertificate=yes;"
        )

        # 获取所有表名
        tables = pd.read_sql("SELECT name FROM sys.tables ORDER BY name", conn)
        print("数据库包含的表：")
        print(tables.to_string(index=False))  # 使用to_string确保完整显示

        # 选择要检查的表
        table_name = input("请输入要查看的表名：")

        # 获取表结构
        schema = pd.read_sql(f"""
            SELECT 
                c.name AS column_name,
                tp.name AS data_type,
                c.max_length,
                c.is_nullable
            FROM sys.columns c
            JOIN sys.tables t ON c.object_id = t.object_id
            JOIN sys.types tp ON c.user_type_id = tp.user_type_id
            WHERE t.name = '{table_name}'
            ORDER BY c.column_id
        """, conn)

        print(f"\n表 {table_name} 的结构：")
        print(schema.to_string(index=False))

        # 获取表数据示例
        sample = pd.read_sql(f"SELECT TOP 5 * FROM [{table_name}]", conn)
        print(f"\n表 {table_name} 的示例数据：")
        print(sample.to_string(index=False))  # 使用to_string确保完整显示

    except Exception as e:
        print(f"错误：{str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()
            # 恢复Pandas默认显示设置（可选）
            pd.reset_option('display.max_columns')
            pd.reset_option('display.max_rows')
            pd.reset_option('display.max_colwidth')
            pd.reset_option('display.width')


# 使用示例
inspect_database(
    server="211.87.227.229",
    database="QQQun",
    username="SA",
    password="QQ12-shegk"
)
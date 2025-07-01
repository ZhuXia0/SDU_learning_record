from flask import Flask, render_template, request, jsonify
import pyodbc
import pandas as pd
from math import ceil

app = Flask(__name__)

# 数据库配置（优化后的连接字符串）
DB_CONFIG = {
    'server': '211.87.227.229',
    'database': 'QQQun',
    'username': 'SA',
    'password': 'QQ12-shegk',
    'driver': 'ODBC Driver 18 for SQL Server',
    'timeout': 30,
    'encrypt': 'yes',  # 强制加密
    'trust_server_certificate': 'yes',  # 信任服务器证书
}

def get_db_connection():
    conn_str = (
        f"DRIVER={DB_CONFIG['driver']};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']};"
        f"Encrypt={DB_CONFIG['encrypt']};"
        f"TrustServerCertificate={DB_CONFIG['trust_server_certificate']};"
        f"Connection Timeout={DB_CONFIG['timeout']}"
    )
    try:
        return pyodbc.connect(conn_str)
    except pyodbc.Error as e:
        print(f"数据库连接失败: {e}")
        raise  # 重新抛出异常，让 Flask 处理

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/query')
def query():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20

        with get_db_connection() as conn:
            total = pd.read_sql("SELECT COUNT(*) AS total FROM [Group]", conn).iloc[0]['total']

            offset = (page - 1) * per_page
            query = f"""
                SELECT TOP {per_page} * FROM [Group]
                WHERE Id NOT IN (
                    SELECT TOP {offset} Id FROM [Group] ORDER BY Id
                )
                ORDER BY Id
            """
            data = pd.read_sql(query, conn).to_dict('records')

            return render_template('query.html',
                                data=data,
                                pagination={
                                    'page': page,
                                    'per_page': per_page,
                                    'total': total,
                                    'pages': ceil(total / per_page)
                                })

    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/api/data')
def api_data():
    try:
        page = request.args.get('page', 1, type=int)
        keyword = request.args.get('keyword', '').strip()
        per_page = 20

        with get_db_connection() as conn:
            base_query = "FROM [Group] WHERE 1=1"
            params = []

            if keyword:
                base_query += " AND (GroupNum LIKE ? OR Title LIKE ? OR Summary LIKE ?)"
                params = [f'%{keyword}%', f'%{keyword}%', f'%{keyword}%']

            count_query = f"SELECT COUNT(*) {base_query}"
            total = int(pd.read_sql(count_query, conn, params=params).iloc[0, 0])

            offset = (page - 1) * per_page
            query = f"""
                SELECT Id, GroupNum, Title, Summary {base_query}
                ORDER BY Id
                OFFSET {offset} ROWS
                FETCH NEXT {per_page} ROWS ONLY
            """
            df = pd.read_sql(query, conn, params=params)
            data = df.astype(object).where(pd.notnull(df), None).to_dict('records')

            return jsonify({
                'success': True,
                'data': data,
                'total': total,
                'page': page
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
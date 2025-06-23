*** Settings ***
Resource          ../common.robot

*** Test Cases ***
TC03_获取问题列表
    [Setup]
    初始化测试会话
    # 1. 登录获取Cookie
    ${login_data}=    Create Dictionary    username=202200201095    password=yangweikang51021
    ${login_resp}=    POST On Session    api_session    /app/appLogin
    ...    json=${login_data}
    ...    headers=${API_HEADERS}
    # 2. 提取JSESSIONID
    ${cookie}=    Get From Dictionary    ${login_resp.cookies}    JSESSIONID
    ${auth_header}=    Create Dictionary    Cookie=JSESSIONID=${cookie}
    # 3. 安全合并字典（避免使用Evaluate）
    ${final_headers}=    Copy Dictionary    ${API_HEADERS}
    Set To Dictionary    ${final_headers}    &{auth_header}
    # 4. 请求数据
    ${params}=    Create Dictionary    page=1    limit=10
    ${response}=    POST On Session    api_session    /app/quesList
    ...    json=${params}
    ...    headers=${final_headers}
    # 5. 验证
    Should Be Equal    ${response.json()["success"]}    ${True}
    Length Should Be    ${response.json()["data"]["pageParam"]["records"]}    10

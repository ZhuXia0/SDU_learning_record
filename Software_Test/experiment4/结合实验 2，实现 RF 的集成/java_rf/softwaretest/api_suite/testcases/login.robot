*** Settings ***
Resource          ../common.robot

*** Test Cases ***
TC01_用户登录成功
    [Setup]    初始化测试会话
    ${test_data}=    Create Dictionary    username=202200201095    password=yangweikang51021
    ${response}=    POST On Session    api_session    /app/appLogin
    ...    json=${test_data}
    ...    headers=${API_HEADERS}
    Should Be Equal    ${response.json()["success"]}    ${True}

TC02_用户登录失败
    [Setup]    初始化测试会话
    ${invalid_data}=    Create Dictionary    username=wrong    password=000000
    ${response}=    POST On Session    api_session    /app/appLogin
    ...    json=${invalid_data}
    ...    headers=${API_HEADERS}
    Should Be Equal As Strings    ${response.json()["message"]}    用户名不存在

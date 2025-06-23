*** Settings ***
Library           RequestsLibrary
Library           Collections

*** Variables ***
${BASE_URL}       http://211.87.232.162:8080

*** Keywords ***
初始化测试会话
    ${headers}=    Create Dictionary    Content-Type=application/json
    Create Session    api_session    ${BASE_URL}
    Set Suite Variable    ${API_HEADERS}    ${headers}

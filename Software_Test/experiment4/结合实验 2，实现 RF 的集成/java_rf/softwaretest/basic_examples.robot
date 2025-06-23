*** Settings ***
Library           BuiltIn
Library           DateTime
Library           OperatingSystem

*** Test Cases ***
Example BuiltIn Operations
    ${message}=    Set Variable    Hello, Robot Framework!
    Log    ${message} # 输出到日志
    ${current_date}=    Get Current Date
    Log    Current date: ${current_date}

Example OS Operations
    Create Directory    ${CURDIR}\\temp_dir
    Directory Should Exist    ${CURDIR}\\temp_dir

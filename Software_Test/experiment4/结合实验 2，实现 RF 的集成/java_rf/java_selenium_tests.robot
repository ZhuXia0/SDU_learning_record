*** Settings ***
Library           Process
Library           OperatingSystem

*** Variables ***
${PROJECT_DIR}    F:/Software_Test/experiment4/rf-lab/java_rf
${CLASSPATH_FILE}    ${PROJECT_DIR}/target/classpath.txt
${JAVA_CLASS}     lab2.KuangStudyIntegratedTest

*** Test Cases ***
执行 Java Selenium 测试套件
    [Documentation]    执行完整的 Java Selenium 测试套件
    # 1. 验证必要文件存在
    File Should Exist    ${CLASSPATH_FILE}
    ...    msg=classpath.txt文件不存在，请先执行mvn dependency:build-classpath
    ${class_file}=    Join Path    ${PROJECT_DIR}    target    classes    lab2    KuangStudyIntegratedTest.class
    File Should Exist    ${class_file}
    ...    msg=未找到编译后的.class文件，请先执行mvn compile
    # 2. 构建完整类路径（包含target/classes）
    ${maven_cp}=    Get File    ${CLASSPATH_FILE}
    ${full_cp}=    Set Variable    ${PROJECT_DIR}/target/classes;${maven_cp}
    Log    完整类路径: ${full_cp}
    # 3. 执行Java测试
    ${result}=    Run Process    java -cp ${full_cp} ${JAVA_CLASS}
    ...    shell=True    timeout=5 min    stderr=STDERR    stdout=STDOUT
    # 4. 处理结果
    Log    Java程序输出:\n${result.stdout}
    Log    Java程序错误:\n${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0
    ...    msg=测试失败！退出码: ${result.rc}\n错误输出: ${result.stderr}

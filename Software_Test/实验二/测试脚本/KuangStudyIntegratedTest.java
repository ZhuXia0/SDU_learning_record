package lab2;

import org.junit.*;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import java.time.Duration;

public class KuangStudyIntegratedTest {
    private static WebDriver driver;
    private static final String BASE_URL = "http://211.87.232.162:8080";

    public static void main(String[] args) {
        // 初始化浏览器
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--remote-allow-origins=*");
        driver = new ChromeDriver(options);
        driver.manage().window().maximize();

        // 执行测试套件
        runAllTests();

        // 关闭浏览器
        driver.quit();
    }
    //每次进行测试前和测试后自动执行的方法
    @Before
    public void setUp() {
        // 初始化浏览器等设置
    }

    @After
    public void tearDown() {
        // 每个测试方法执行后清除登录状态
        logout();
        // 关闭浏览器等清理工作
    }



//     === 测试用例实现 ===
    @Test
    public void TC001_NavigationToQuestionPage() {
        driver.get(BASE_URL);
        driver.findElement(By.linkText("问答")).click();
        //未登录点击问答
        if (driver.getCurrentUrl().contains("toLogin")) {
            System.out.println("✅TC001: 未登录跳转正确");
        } else if (driver.getCurrentUrl().contains("question")) {
            System.out.println("❌TC001: 未登录跳转错误");
        } else {
            Assert.fail("TC001: 跳转异常");
        }
        logout();
        login();
        //登录之后点击问答

        driver.findElement(By.linkText("问答")).click();

        if (driver.getCurrentUrl().contains("toLogin")) {
            System.out.println("❌TC001: 登录跳转失败");
        } else if (driver.getCurrentUrl().contains("question")) {
            System.out.println("✅TC001通过: 登录跳转正确");
        } else {
            Assert.fail("TC001: 跳转异常");
        }
    }

    @Test
    public void TC002_UnauthorizedBlogEditAccess() {
        driver.get(BASE_URL + "/blog/write");
        Assert.assertTrue("TC002: 应返回403或跳转登录",
                driver.getCurrentUrl().contains("login") ||
                        driver.getPageSource().contains("403"));
    }

    @Test
    public void TC003_LoginWithInvalidPassword() {
        driver.get(BASE_URL + "/toLogin");
        driver.findElement(By.name("username")).sendKeys("202200201095");
        driver.findElement(By.name("password")).sendKeys("123456");//这是错误密码
        driver.findElement(By.cssSelector("button[type='submit']")).click();

        try {
            WebElement error = new WebDriverWait(driver, Duration.ofSeconds(2))
                    .until(ExpectedConditions.visibilityOfElementLocated(
                            By.className("error-message")));
            System.out.println("TC003: 错误提示显示正常");
        } catch (TimeoutException e) {
            Assert.fail("TC003: 未显示密码错误提示");
        }
        logout();
    }
    @Test
    public void TC004_EmptyQuestionTitle() {
        // 1. 登录并进入提问页面
        login();
        driver.get(BASE_URL + "/question/write");
        new WebDriverWait(driver, Duration.ofSeconds(10))
                .until(ExpectedConditions.urlContains(BASE_URL + "/question/write"));


        // 2. 显式等待页面加载完成（通过标题输入框判断）
        new WebDriverWait(driver, Duration.ofSeconds(5))
                .until(ExpectedConditions.presenceOfElementLocated(
                        By.cssSelector("input[name='title']")));

        // 3. 直接点击发布按钮（使用更精确的选择器）
        WebElement submitBtn = new WebDriverWait(driver, Duration.ofSeconds(3))
                .until(ExpectedConditions.elementToBeClickable(
                        By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
        submitBtn.click();

        // 4. 验证必填提示
        String validationMessage = driver.findElement(By.name("title"))
                .getAttribute("validationMessage");
        Assert.assertEquals("请填写此字段。", validationMessage);
        System.out.println("✅TC004: 具有空标题提示");

        logout();
    }
    @Test
    public void TC005_DownloadLinkFunction() {
        try {
            login();
            driver.get(BASE_URL + "/download");
            String currentUrl = driver.getCurrentUrl();
            WebElement downloadBtn = driver.findElement(By.xpath("//a[contains(text(),'提取码')]"));
            downloadBtn.click();

            // 验证页面是否跳转
            new WebDriverWait(driver, Duration.ofSeconds(2))
                    .until(ExpectedConditions.not(ExpectedConditions.urlToBe(currentUrl)));
            Assert.assertNotEquals("点击提取码按钮应跳转", currentUrl, driver.getCurrentUrl());
        } catch (TimeoutException e) {
            // 自定义错误消息
            Assert.fail("点击提取码按钮后页面未按预期跳转。当前 URL: " + driver.getCurrentUrl());
        }
        logout();
    }
    @Test
    public void TC006_LongContentSubmission() {

        login();
        driver.get(BASE_URL + "/blog/write");
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        // 测试超长标题
            WebElement title = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='title']")));
            String longTitle = new String(new char[1001]).replace("\0", "a");
            title.sendKeys(longTitle);
            Thread.sleep(1000);//如果不暂停两秒会导致标题无法填写
        // 测试超长内容
            String longContent = new String(new char[1001]).replace("\0", "a");

            //通过Editor.md的API设置内容
            ((JavascriptExecutor)driver).executeScript(
                    "testEditor.setMarkdown(arguments[0]);", longContent);
            Thread.sleep(1000);

            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
            submitBtn.click();

        // 检查是否有内容超出限制的提示

            String contentValidationMessage = driver.findElement(By.id("title")).getAttribute("validationMessage");
            Assert.assertEquals("内容超出限制的提示应显示", "内容超出限制", contentValidationMessage);
            System.out.println("✅TC006: 具有内容超出限制的提示");
        } catch (Exception e) {
            // 如果没有找到内容超出限制的提示，则测试失败
            Assert.fail("TC006: 没有内容超出限制的提示而是直接页面失效");
        }
        logout();
    }
    @Test
    public void TC007_LoginXSSAttackAttempt() {
        try {
            // 1. 访问登录页面
            driver.get(BASE_URL + "/toLogin");

            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(2));

            // 2. 在用户名字段输入XSS攻击脚本
            WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='username']")));
            usernameField.sendKeys("<script>alert(1)</script>");

            // 3. 输入任意密码（XSS测试主要针对用户名字段）
            WebElement passwordField = driver.findElement(By.cssSelector("input[name='password']"));
            passwordField.sendKeys("test123");

            // 4. 提交登录表单
            WebElement loginBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit']")));
            loginBtn.click();

            // 5. 验证结果
            try {
                // 检查是否有alert弹窗出现（不应该出现）
                Alert alert = wait.until(ExpectedConditions.alertIsPresent());
                Assert.fail("TC007失败：系统未过滤XSS脚本，出现了alert弹窗");
            } catch (TimeoutException e) {
                // 预期情况：没有alert弹窗

                // 检查是否重定向或停留在登录页
                if (!driver.getCurrentUrl().contains("/login")) {
                    // 检查页面内容是否包含非法输入提示
                    try {
                        WebElement errorMsg = wait.until(ExpectedConditions.presenceOfElementLocated(
                                By.xpath("//*[contains(text(),'非法') or contains(text(),'无效')]")));
                        System.out.println("✅TC007通过：系统检测到非法输入并提示 - " + errorMsg.getText());
                    } catch (Exception ex) {
                        // 检查输入是否被过滤（查看页面元素中的值）
                        WebElement usernameValue = driver.findElement(By.cssSelector("input[name='username']"));
                        String value = usernameValue.getAttribute("value");
                        if (value.contains("<script>")) {
                            Assert.fail("TC007失败：系统未过滤XSS脚本，输入值保留原样");
                        } else {
                            System.out.println("✅TC007通过：系统已过滤XSS脚本，输入值被清理");
                        }
                    }
                } else {
                    System.out.println("✅TC007通过：系统阻止了XSS攻击尝试");
                }
            }

        } catch (Exception e) {
            Assert.fail("TC007执行失败：" + e.getMessage());
        }
    }
    //@Test
    public void TC008_MobileNavMenuToggle() {
        try {
            // 1. 访问首页
            driver.get(BASE_URL + "/index");

            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));

            // 2. 设置浏览器为移动端尺寸（模拟手机视图）
            driver.manage().window().setSize(new Dimension(375, 812)); // iPhone X 尺寸

            // 3. 定位汉堡菜单按钮
            WebElement hamburgerBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".navbar-toggler")));

            // 4. 首次点击 - 展开菜单
            hamburgerBtn.click();
            Thread.sleep(1000); // 等待动画完成

            // 验证菜单是否展开
            WebElement navMenu = driver.findElement(By.id("navbarsExample07"));
            boolean isExpanded1 = navMenu.getAttribute("class").contains("show");
            Assert.assertTrue("TC008失败：首次点击后菜单未展开",isExpanded1);

            // 5. 再次点击 - 折叠菜单
            hamburgerBtn.click();
            Thread.sleep(1000); // 等待动画完成

            // 验证菜单是否折叠
            boolean isExpanded2 = navMenu.getAttribute("class").contains("show");
            Assert.assertFalse("TC008失败：再次点击后菜单未折叠",isExpanded2);

            System.out.println("✅TC008通过：移动端导航菜单可正常展开/折叠");

        } catch (Exception e) {
            Assert.fail("TC008执行失败：" + e.getMessage());
        } finally {
            // 恢复浏览器窗口大小
            driver.manage().window().maximize();
        }
    }
    @Test
    public void TC009_NavigationToSayPage() {
        driver.get(BASE_URL+"/say");

        //未登录点击问答
        if (driver.getCurrentUrl().contains("toLogin")) {
            System.out.println("✅TC009: 未登录自动跳转登录页");
        } else {
            Assert.fail("TC009通过: 跳转异常");
        }
        logout();
    }

    @Test
    public void TC010_BackToTopButtonFunction() {
        login();
        try {
            // 1. 访问页面
            driver.get(BASE_URL + "/blog");
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));

            // 2. 滚动到底部
            ((JavascriptExecutor)driver).executeScript("window.scrollTo(0, document.body.scrollHeight)");
            Thread.sleep(1000);

            // 3. 验证按钮可见性
            WebElement backToTopBtn = wait.until(ExpectedConditions.visibilityOfElementLocated(
                    By.cssSelector(".to-top")));
            Assert.assertTrue("TC010失败：滚动后未显示返回顶部按钮", backToTopBtn.isDisplayed());

            // 4. 获取初始滚动位置（使用Number接收避免类型问题）
            Number initialScrollY = (Number)((JavascriptExecutor)driver)
                    .executeScript("return window.pageYOffset;");

            // 5. 点击按钮
            backToTopBtn.click();

            // 6. 使用动态等待直到滚动到顶部附近
            wait.until(d -> {
                Number currentY = (Number)((JavascriptExecutor)driver)
                        .executeScript("return window.pageYOffset;");
                return currentY.doubleValue() < 50;
            });

            // 7. 验证最终位置
            Number finalScrollY = (Number)((JavascriptExecutor)driver)
                    .executeScript("return window.pageYOffset;");

            Assert.assertTrue(
                    "TC010失败：未成功返回页面顶部（最终位置：" + finalScrollY + "px）",
                    finalScrollY.doubleValue() < 50
            );

            System.out.println(String.format(
                    "✅TC010通过：从 %.0fpx 滚动到 %.0fpx",
                    initialScrollY.doubleValue(),
                    finalScrollY.doubleValue()
            ));

        } catch (Exception e) {
            Assert.fail("TC010执行失败：" + e.toString()); // 使用toString()获取完整异常信息
        }
        logout();
    }
    @Test
    public void TC011_RememberPasswordFunction() {
        try {
            // 第一次登录（手动勾选记住密码）
            driver.get(BASE_URL + "/toLogin");
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // 输入凭证
            WebElement usernameInput = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.name("username")));
            WebElement passwordInput = driver.findElement(By.name("password"));
            usernameInput.sendKeys("202200201095");
            passwordInput.sendKeys("yangweikang51021");

            // 勾选记住密码（原login函数不包含此操作）
            WebElement rememberCheckbox = driver.findElement(By.name("remember"));
            if (!rememberCheckbox.isSelected()) {
                rememberCheckbox.click();
            }

            // 提交登录（使用原login函数中的选择器）
            WebElement submitButton = wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector("button[type='submit']")));
            submitButton.click();
            wait.until(ExpectedConditions.urlContains("/index"));
            //System.out.println("✅ 第一次登录成功（已勾选记住密码）");

            // 使用现有logout函数登出
            logout();

            // 重新访问登录页验证自动填充
            driver.get(BASE_URL + "/toLogin");

            // 获取自动填充值
            usernameInput = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.name("username")));
            passwordInput = driver.findElement(By.name("password"));
            String savedUsername = usernameInput.getAttribute("value");
            String savedPassword = passwordInput.getAttribute("value");

            // 验证结果
            if (savedUsername.equals("202200201095")) {
                if (!savedPassword.isEmpty()) {
                    System.out.println("✅ TC011通过：用户名和密码被正确记住");
                } else {
                    System.out.println("⚠️ TC011部分通过：用户名被记住，但密码字段受浏览器保护");
                }
            } else {
                Assert.fail("TC011失败：用户名未被自动填充（实际值：" + savedUsername + "）");
            }

            // 清理状态（使用标准登录流程覆盖记住密码状态）
            login(); // 使用原login函数（不勾选记住密码）
            logout();

        } catch (Exception e) {
            Assert.fail("TC011执行失败：" + e.getMessage());
        }
    }
    @Test
    public void TC012_BlogContentXSSAttack() {
        login();
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // 1. 进入博客发布页
            driver.get(BASE_URL + "/blog/write");

            // 2. 设置唯一标题（带时间戳）
            String blogTitle = "XSS测试-" + System.currentTimeMillis();
            WebElement title = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='title']")));
            title.sendKeys(blogTitle);
            Thread.sleep(1000);

            // 3. 注入XSS内容
            String xssContent = "<script>alert('XSS')</script>";
            ((JavascriptExecutor)driver).executeScript(
                    "testEditor.setMarkdown(arguments[0]);", xssContent);
            Thread.sleep(1000);

            // 4. 提交文章
            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
            submitBtn.click();

            // 5. 等待发布完成（跳转到博客列表页）
            wait.until(ExpectedConditions.urlContains("/blog"));

            // 6. 通过导航菜单进入个人中心
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();

            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'个人中心')]"))).click();

            // 7. 切换到"我的博客"标签页
            WebElement blogTab = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(@href,'/user/blog') and contains(@class,'active')]")));
            ((JavascriptExecutor)driver).executeScript("arguments[0].click();", blogTab);

            // 8. 定位并访问最新发布的博客
            WebElement latestBlog = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.xpath("//div[@class='media text-muted pt-3']//a[contains(text(),'" + blogTitle + "')]")));
            String blogUrl = latestBlog.getAttribute("href");
            driver.get(blogUrl);

            // 9. 验证XSS防护

                Alert alert = wait.until(ExpectedConditions.alertIsPresent());
                Assert.fail("TC012失败：检测到XSS脚本执行");
        } catch (TimeoutException e) {
            System.out.println("✅TC012通过：系统成功防御了XSS攻击");
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            logout();
        }
    }
    @Test
    public void TC013_MarkdownCodeBlockWithJS() {
        login();
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // 1. 进入博客发布页
            driver.get(BASE_URL + "/blog/write");

            // 2. 设置唯一标题（带时间戳）
            String blogTitle = "Markdown代码块测试-" + System.currentTimeMillis();
            WebElement title = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='title']")));
            title.sendKeys(blogTitle);
            Thread.sleep(1000);

            // 3. 注入Markdown代码块中的JS内容
            String markdownContent = "```html\n<script>alert(1)</script>\n```";
            ((JavascriptExecutor)driver).executeScript(
                    "testEditor.setMarkdown(arguments[0]);", markdownContent);
            Thread.sleep(1000);

            // 4. 提交文章
            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
            submitBtn.click();

            // 5. 等待发布完成（跳转到博客列表页）
            wait.until(ExpectedConditions.urlContains("/blog"));

            // 6. 通过导航菜单进入个人中心
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();

            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'个人中心')]"))).click();

            // 7. 切换到"我的博客"标签页
            WebElement blogTab = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(@href,'/user/blog') and contains(@class,'active')]")));
            ((JavascriptExecutor)driver).executeScript("arguments[0].click();", blogTab);

            // 8. 定位并访问最新发布的博客
            WebElement latestBlog = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.xpath("//div[@class='media text-muted pt-3']//a[contains(text(),'" + blogTitle + "')]")));
            String blogUrl = latestBlog.getAttribute("href");
            driver.get(blogUrl);

            // 9. 验证Markdown代码块中的JS未执行
            try {
                // 尝试等待alert出现，如果超时则视为安全通过
                Alert alert = wait.until(ExpectedConditions.alertIsPresent());
                System.out.println("❌ TC013失败：检测到Markdown代码块中的JS脚本执行");
                alert.accept();
            } catch (TimeoutException e) {
                // 超时异常，表示没有弹出alert，视为安全通过
                System.out.println("✅TC013通过：Markdown代码块中的JS脚本未执行");
            }


        } catch (Exception e) {
            // 处理登录或其他前期步骤中的异常
            System.out.println("❌ TC013执行异常：" + e.getMessage());
            Assert.fail("TC013执行异常：" + e.getMessage());
        } finally {
            logout();
        }
    }
    @Test
    public void TC014_ImageTagWithOnerrorEvent() {
        login();
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // 1. 进入博客发布页
            driver.get(BASE_URL + "/blog/write");
            Thread.sleep(1000);
            // 2. 设置唯一标题（带时间戳）
            String blogTitle = "图片标签onerror测试-" + System.currentTimeMillis();
            WebElement title = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='title']")));
            title.sendKeys(blogTitle);
            Thread.sleep(2000);

            // 3. 注入带有onerror事件的图片标签
            String markdownContent = "<!-- 样本1：利用onerror事件 -->\n" +
                    "<img src=\"x\"\n" +
                    "style=\"display:none\"\n" +
                    "onerror=\"while(1) alert('死循环弹窗！')\">\n";
            ((JavascriptExecutor)driver).executeScript(
                    "testEditor.setMarkdown(arguments[0]);", markdownContent);
            Thread.sleep(1000);

            // 4. 提交文章
            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
            submitBtn.click();

            // 5. 等待发布完成（跳转到博客列表页）
            wait.until(ExpectedConditions.urlContains("/blog"));

            // 6. 通过导航菜单进入个人中心
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();

            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'个人中心')]"))).click();

            // 7. 切换到"我的博客"标签页
            WebElement blogTab = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(@href,'/user/blog') and contains(@class,'active')]")));
            ((JavascriptExecutor)driver).executeScript("arguments[0].click();", blogTab);

            // 8. 定位并访问最新发布的博客
            WebElement latestBlog = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.xpath("//div[@class='media text-muted pt-3']//a[contains(text(),'" + blogTitle + "')]")));
            String blogUrl = latestBlog.getAttribute("href");
            driver.get(blogUrl);

            // 9. 验证onerror事件未触发
            try {
                // 尝试等待alert出现，如果超时则视为安全通过
                Alert alert = wait.until(ExpectedConditions.alertIsPresent());
                driver.quit();

                // 重新初始化浏览器
                ChromeOptions options = new ChromeOptions();
                options.addArguments("--remote-allow-origins=*");
                driver = new ChromeDriver(options);
                driver.manage().window().maximize();
                // 重新导航到基准URL
                driver.get(BASE_URL);
                Assert.fail("TC014执行异常：检测到未处理的弹窗");
            } catch (TimeoutException e) {
                // 超时异常，表示没有弹出alert，视为安全通过
                System.out.println("✅TC014通过：onerror事件未触发");
            }
        } catch (Exception e) {
            // 处理其他异常
            System.out.println("❌ TC014执行异常：" + e.getMessage());
            Assert.fail("TC014执行异常：" + e.getMessage());
        }  finally {
            logout();
        }
    }
    @Test
    public void TC015_ImageTagWithOnloadEvent() {
        login();
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // 1. 进入博客发布页
            driver.get(BASE_URL + "/blog/write");
            Thread.sleep(1000);
            // 2. 设置唯一标题（带时间戳）
            String blogTitle = "图片标签onload测试-" + System.currentTimeMillis();
            WebElement title = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector("input[name='title']")));
            title.sendKeys(blogTitle);
            Thread.sleep(1000);

            // 3. 注入带有onload事件的图片标签
            String markdownContent = "<!-- 样本2：利用onload事件（需图片能加载） -->\n" +
                    "<img src=\"https://picsum.photos/200\"\n" +
                    "onload=\"document.location='https://www.sdu.edu.cn/'\">\n";
            ((JavascriptExecutor)driver).executeScript(
                    "testEditor.setMarkdown(arguments[0]);", markdownContent);
            Thread.sleep(1000);

            // 4. 提交文章
            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//button[@type='submit' and contains(@class, 'btn-primary')]")));
            submitBtn.click();

            // 5. 等待发布完成（跳转到博客列表页）
            wait.until(ExpectedConditions.urlContains("/blog"));

            // 6. 通过导航菜单进入个人中心
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();

            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'个人中心')]"))).click();

            // 7. 切换到"我的博客"标签页
            WebElement blogTab = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(@href,'/user/blog') and contains(@class,'active')]")));
            ((JavascriptExecutor)driver).executeScript("arguments[0].click();", blogTab);

            // 8. 定位并访问最新发布的博客
            WebElement latestBlog = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.xpath("//div[@class='media text-muted pt-3']//a[contains(text(),'" + blogTitle + "')]")));
            String blogUrl = latestBlog.getAttribute("href");
            driver.get(blogUrl);

            // 9. 验证onload事件未触发（页面未跳转）
            // 等待一段时间以确保页面没有跳转
            Thread.sleep(10000);
            if (!driver.getCurrentUrl().equals(blogUrl)) {
                Assert.fail("TC015失败：检测到onload事件执行，页面跳转" );

            } else {
                System.out.println("✅TC015通过：onload事件未触发");
            }
        } catch (Exception e) {
            // 处理登录或其他前期步骤中的异常
            System.out.println("❌ TC015执行异常：" + e.getMessage());
            Assert.fail("TC015执行异常：" + e.getMessage());
        } finally {
            logout();
        }
    }
    @Test
    public void TC016_UserProfileUpdate() {
        login();
        try {
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(3));

            // === 第一部分：测试个人资料更新 ===
            // 1. 导航到资料更新页面
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'更新资料')]"))).click();

            // 2. 填写新的测试数据
            String newNickname = "测试用户" + System.currentTimeMillis();
            String newIntro = "自动化测试简介 " ;

            WebElement nicknameField = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.id("nickname")));
            nicknameField.clear();
            nicknameField.sendKeys(newNickname);

            WebElement introField = driver.findElement(By.name("intro"));
            introField.clear();
            introField.sendKeys(newIntro);

            // 3. 提交更新
            WebElement submitBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector("button[type='submit']")));
            submitBtn.click();

            // 4. 验证更新结果
            try {
                wait.until(ExpectedConditions.textToBePresentInElementLocated(
                        By.cssSelector(".alert-success"), "更新成功"));
                System.out.println("✅ 个人资料更新成功");
            } catch (TimeoutException e) {
                Assert.fail("个人资料更新失败，未显示成功提示");
            }

            // === 第二部分：测试头像上传功能 ===
            // 1. 导航到头像上传页面
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.cssSelector(".nav-link.dropdown-toggle"))).click();
            wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'头像上传')]"))).click();

            // 2. 验证上传表单元素是否存在
            try {
                // 检查文件上传输入框
                WebElement fileInput = wait.until(ExpectedConditions.presenceOfElementLocated(
                        By.cssSelector("input[type='file']")));
                System.out.println("✅ 检测到头像上传输入框");

                // 检查提交按钮
                WebElement uploadBtn = wait.until(ExpectedConditions.elementToBeClickable(
                        By.cssSelector("button[type='submit']")));
                System.out.println("✅ 检测到上传提交按钮");

                // 检查预览区域（如果有）
                try {
                    WebElement preview = driver.findElement(By.cssSelector(".avatar-preview"));
                    System.out.println("✅ 检测到头像预览区域");
                } catch (NoSuchElementException e) {
                    System.out.println("⚠️ 未检测到头像预览功能");
                }

            } catch (TimeoutException e) {
                Assert.fail("TC016失败：未找到头像上传功能所需元素");
            }

            // === 第三部分：验证昵称同步 ===
            // 1. 导航到博客页面
            driver.get(BASE_URL + "/blog");

            // 2. 检查显示的昵称
            try {
                WebElement displayedName = wait.until(ExpectedConditions.presenceOfElementLocated(
                        By.cssSelector(".navbar-nav span:not(.badge)")));
                if (!displayedName.getText().equals(newNickname)) {
                    System.out.println("⚠️ 昵称未同步显示（当前显示：" + displayedName.getText() + "）");
                    Assert.fail("TC016部分失败：昵称未同步到其他页面");
                } else {
                    System.out.println("✅ 昵称已同步显示");
                }
            } catch (Exception e) {
                Assert.fail("昵称同步检查失败：" + e.getMessage());
            }

        } catch (Exception e) {
            Assert.fail("TC016执行失败：" + e.getMessage());
        } finally {
            logout();
        }
    }



    // === 辅助方法 ===
    private static void runAllTests() {
        Result result = JUnitCore.runClasses(KuangStudyIntegratedTest.class);

        System.out.println("\n=== 测试结果汇总 ===");
        System.out.println("执行总数: " + result.getRunCount());
        System.out.println("失败数: " + result.getFailureCount());

        for (Failure failure : result.getFailures()) {
            System.out.println("\n❌ 失败: " + failure.getDescription());
            System.out.println(failure.getException());
        }

        System.out.println("\n通过率: " +
                (result.getRunCount() - result.getFailureCount()) * 100 / result.getRunCount() + "%");
    }

    private static void login() {
        // 1. 导航到登录页面
        driver.get(BASE_URL + "/toLogin");

        // 2. 等待用户名输入框加载并输入用户名
        WebElement usernameInput = new WebDriverWait(driver, Duration.ofSeconds(10))
                .until(ExpectedConditions.presenceOfElementLocated(
                        By.name("username")));
        usernameInput.sendKeys("202200201095");

        // 3. 等待密码输入框加载并输入密码
        WebElement passwordInput = new WebDriverWait(driver, Duration.ofSeconds(10))
                .until(ExpectedConditions.presenceOfElementLocated(
                        By.name("password")));
        passwordInput.sendKeys("yangweikang51021");

        // 4. 等待提交按钮可点击并点击
        WebElement submitButton = new WebDriverWait(driver, Duration.ofSeconds(10))
                .until(ExpectedConditions.elementToBeClickable(
                        By.cssSelector("button[type='submit']")));
        submitButton.click();

        // 5. 等待登录成功后重定向到主页

        new WebDriverWait(driver, Duration.ofSeconds(10))
                .until(ExpectedConditions.urlContains(BASE_URL+"/index"));
    }
    private static void logout() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(1));

        // 1. 检查当前是否已登录（通过判断导航栏是否显示用户头像）
        try {
            WebElement userAvatar = wait.until(ExpectedConditions.presenceOfElementLocated(
                    By.cssSelector(".navbar-nav img[src*='avatar']")));

            // 2. 点击用户头像展开下拉菜单
            WebElement userDropdown = driver.findElement(By.cssSelector(".nav-link.dropdown-toggle"));
            userDropdown.click();

            // 3. 点击注销按钮
            WebElement logoutBtn = wait.until(ExpectedConditions.elementToBeClickable(
                    By.xpath("//a[contains(text(),'注销')]")));
            logoutBtn.click();

            // 4. 等待返回登录页或首页
            wait.until(ExpectedConditions.or(
                    ExpectedConditions.urlContains("/toLogin"),
                    ExpectedConditions.urlContains("/index")
            ));

            System.out.println("✅ 已通过导航菜单完成注销");

        } catch (TimeoutException e) {
            // 如果未找到用户头像，说明当前未登录

            driver.get(BASE_URL + "/toLogin"); // 确保回到登录页
        }
        driver.manage().deleteAllCookies();
        driver.get(BASE_URL);
        // 其他登出操作...
    }


}
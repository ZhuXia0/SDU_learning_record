#include <iostream>
#include <string>

using namespace std;

int main() {
    string s;
    while (getline(cin, s)) { // 逐行读取直到 EOF
        bool escape = false; // 是否处于转义状态

        for (size_t i = 0; i < s.size(); ++i) {
            if (escape) {
                switch (s[i]) {
                    case 'n':
                        cout << '\n';
                        break;
                    case 't':
                        cout << '\t';
                        break;
                    case '?':
                        cout << '?';
                        break;
                    case '\'':
                        cout << '\'';
                        break;
                    case '\"':
                        cout << '\"';
                        break;
                    case '\\':
                        cout << '\\';
                        break;
                    default:
                        // 非法转义，输出原样
                        cout << '\\' << s[i];
                        break;
                }
                escape = false; // 重置转义状态
            } else {
                if (s[i] == '\\') {
                    escape = true; // 遇到 \ ，进入转义状态
                } else {
                    cout << s[i];
                }
            }
        }
        if (!escape) cout << endl; // 每行结束输出换行（除非最后一个字符是转义符）
    }

    return 0;
}
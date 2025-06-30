#include <iostream>
#include <cstdlib> // 用于abs函数
using namespace std;

long long gcd(long long a, long long b) {
    // 处理0的情况
    if (a == 0) return abs(b);
    if (b == 0) return abs(a);
    
    // 辗转相除法
    return gcd(b, a % b);
}

int main() {
    int N;
    cin >> N;
    while (N--) {
        long long a, b;
        cin >> a >> b;
        cout << gcd(a, b) << '\n';
    }
    return 0;
}
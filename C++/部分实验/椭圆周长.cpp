#include <iostream>
#include <iomanip>
#include <cmath>

using namespace std;

const int N = 100000; // 分段数量，越大越精确
const double PI = acos(-1.0);

double ellipse_perimeter(double a, double b) {
    double length = 0.0;
    double dtheta = 2 * PI / N;

    double prev_x = a * cos(0);
    double prev_y = b * sin(0);

    for (int i = 1; i <= N; ++i) {
        double theta = i * dtheta;
        double x = a * cos(theta);
        double y = b * sin(theta);

        double dx = x - prev_x;
        double dy = y - prev_y;

        length += sqrt(dx * dx + dy * dy);

        prev_x = x;
        prev_y = y;
    }

    return length;
}

int main() {
    int T;
    cin >> T;

    while (T--) {
        double a, b;
        cin >> a >> b;

        double perimeter = ellipse_perimeter(a, b);
        cout << fixed << setprecision(6) << perimeter << endl;
    }

    return 0;
}
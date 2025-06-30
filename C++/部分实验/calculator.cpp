#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cctype>

using namespace std;

vector<string> split(const string &s) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (tokenStream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

int calculate(const vector<string>& tokens) {
    vector<int> numbers;
    vector<char> ops;
    
    // First, parse numbers and operators
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i % 2 == 0) {
            numbers.push_back(stoi(tokens[i]));
        } else {
            ops.push_back(tokens[i][0]);
        }
    }
    
    // First pass: handle * and /
    for (size_t i = 0; i < ops.size(); ) {
        char op = ops[i];
        if (op == '*' || op == '/') {
            int a = numbers[i];
            int b = numbers[i + 1];
            int res = (op == '*') ? a * b : a / b;
            numbers[i] = res;
            numbers.erase(numbers.begin() + i + 1);
            ops.erase(ops.begin() + i);
        } else {
            ++i;
        }
    }
    
    // Second pass: handle + and -
    int result = numbers[0];
    for (size_t i = 0; i < ops.size(); ++i) {
        char op = ops[i];
        int b = numbers[i + 1];
        if (op == '+') {
            result += b;
        } else {
            result -= b;
        }
    }
    
    return result;
}

int main() {
    int N;
    cin >> N;
    cin.ignore(); // Ignore the newline after N
    
    for (int i = 0; i < N; ++i) {
        string expr;
        getline(cin, expr);
        vector<string> tokens = split(expr);
        
        if (tokens.size() == 1) {
            cout << tokens[0] << endl;
            continue;
        }
        
        int result = calculate(tokens);
        cout << result << endl;
    }
    
    return 0;
}
#include <iostream>
#include <string>
#include <cctype> 

using namespace std;

bool isValidIdentifier(const string& s) {
    if (s.empty()) return false;

    
    if (!isalpha(s[0]) && s[0] != '_') return false;


    for (size_t i = 1; i < s.size(); ++i) {
        if (!isalnum(s[i]) && s[i] != '_') return false;
    }

    return true;
}

int main() {
    string s;
    
    while (getline(cin, s)) {
        if (isValidIdentifier(s)) {
            cout << 1 << endl;
        } else {
            cout << 0 << endl;
        }
    }

    return 0;
}
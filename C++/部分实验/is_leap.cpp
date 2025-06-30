#include<iostream>
using namespace std;


const int N=100000;

bool judge_year(int x)
{
    if(x%4==0&&x%100!=0||x%400==0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int main()
{
    int n;
    int year[N];
    cin>>n;
    for(int i=0;i<n;i++)
    {
        cin>>year[i];
    }
    for(int i=0;i<n;i++)
    {
        if(judge_year(year[i]))
        {
            cout<<"Yes"<<endl;
        }
        else
        {
            cout<<"No"<<endl;
        }
        
    }
}
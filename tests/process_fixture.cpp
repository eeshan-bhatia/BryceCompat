#include <windows.h>
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int) {
    HWND window=CreateWindowExW(0,L"STATIC",L"Synthetic diagnostic fixture",WS_OVERLAPPEDWINDOW,0,0,200,100,nullptr,nullptr,instance,nullptr);
    if(!window)return 1;
    auto start=GetTickCount64();
    while(GetTickCount64()-start<1500) {
        MSG msg{};while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}
        Sleep(5);
    }
    if(!DestroyWindow(window))return 2;
    return 37;
}

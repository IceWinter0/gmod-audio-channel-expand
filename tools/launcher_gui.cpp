#include "loader_session.hpp"
#include "steam_discovery.hpp"
#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <sstream>
#include <fstream>
#include <algorithm>
using namespace channel_expand;
using namespace channel_expand::loader;
namespace {
constexpr UINT EventMessage=WM_APP+1;
enum Id {Install=101,Browse,Refresh,Ack,Clear,Start,Cancel,Log,Copy};
struct Command {enum Kind {Discover,Manual,Launch} kind;std::wstring root;LoaderConfig config;};
struct Event {enum Kind {Found,Status,Error,Finished} kind;DiscoveryResult discovery;LoaderConfig config;SessionEvent session;std::wstring message;};
struct App {
 HWND window{},combo{},browse{},refresh{},start{},cancel{},log{},copy{},title{},version{},phase{},metrics{},detail{},warning{};HFONT font{},heading{};int dpi=96;
 std::mutex mutex;std::condition_variable wake;std::deque<Command> commands;std::deque<Event> events;std::thread worker;std::atomic<bool> stop{},done{},cancel_requested{};LoaderSession session;
 DiscoveryResult installs;LoaderConfig config;std::wstring diagnostics,logpath;bool busy{},closing{},monitor{},smoke{};ULONGLONG sampled{};
 void Push(Event e){{std::lock_guard<std::mutex> lock(mutex);events.push_back(std::move(e));}PostMessageW(window,EventMessage,0,0);}
 void Queue(Command c){{std::lock_guard<std::mutex> lock(mutex);commands.push_back(std::move(c));}wake.notify_one();}
 void Run(){bool monitoring=false;const auto sink=[&](const SessionEvent& s){Event e{};e.kind=Event::Status;e.session=s;Push(std::move(e));if(stop.load()||cancel_requested.load())session.Cancel();};
  while(!stop.load()) {Command c{};bool has=false;{std::unique_lock<std::mutex> lock(mutex);wake.wait_for(lock,std::chrono::milliseconds(monitoring?2000:1000),[&]{return stop.load()||!commands.empty();});if(stop.load())break;if(!commands.empty()){c=std::move(commands.front());commands.pop_front();has=true;}}
   try {if(has){if(c.kind==Command::Discover||c.kind==Command::Manual){Event e{};e.kind=Event::Found;e.config=LoadConfig(Home().wstring());if(c.kind==Command::Discover)e.discovery=DiscoverSteamInstalls();else{auto candidate=ValidateInstallRoot(c.root);candidate.source=L"手动选择";e.discovery.candidates.push_back(std::move(candidate));}
      const auto hash=ValidatePackage(Home().wstring());e.config.hash=hash;e.config.acknowledged=true;e.config.clear_once=true;if(e.config.module.empty()||!std::filesystem::exists(e.config.module))e.config.module=DefaultModulePath(Home().wstring());VerifyModule(e.config);Push(std::move(e));
    }else{if(!ValidateInstallRoot(std::filesystem::path(c.config.game).parent_path().parent_path().parent_path().wstring()).supported)throw std::runtime_error("game compatibility changed; refresh installation");session.Start(c.config,sink);monitoring=true;}}
    else if(monitoring){session.Query(sink);if(!session.Running())monitoring=false;}
   }catch(const std::exception& ex){monitoring=false;Event e{};e.kind=Event::Error;e.message=Wide(ex.what());Push(std::move(e));}
   if(has){Event e{};e.kind=Event::Finished;Push(std::move(e));}
  }
  done.store(true);PostMessageW(window,EventMessage,0,0);
 }
};
int Scale(App& a,int n){return MulDiv(n,a.dpi,96);}
void Text(HWND w,const std::wstring& s){SetWindowTextW(w,s.c_str());}
HWND Control(App& a,const wchar_t* cls,const wchar_t* label,DWORD style,int id=0){return CreateWindowExW(cls==std::wstring(L"EDIT")?WS_EX_CLIENTEDGE:0,cls,label,WS_CHILD|WS_VISIBLE|style,0,0,10,10,a.window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);}
void Fonts(App& a){if(a.font)DeleteObject(a.font);if(a.heading)DeleteObject(a.heading);a.font=CreateFontW(-Scale(a,15),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");a.heading=CreateFontW(-Scale(a,23),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");for(HWND w=GetWindow(a.window,GW_CHILD);w;w=GetWindow(w,GW_HWNDNEXT))SendMessageW(w,WM_SETFONT,reinterpret_cast<WPARAM>(a.font),TRUE);SendMessageW(a.title,WM_SETFONT,reinterpret_cast<WPARAM>(a.heading),TRUE);}
void Layout(App& a){RECT r{};GetClientRect(a.window,&r);const int m=Scale(a,24),gap=Scale(a,10),width=r.right-2*m;const auto place=[&](HWND w,int x,int y,int cx,int cy){MoveWindow(w,x,y,cx,cy,TRUE);};const auto y=[&](int n){return Scale(a,n);};
 place(a.title,m,y(20),width,y(36));place(a.version,m,y(60),width,y(26));
 const int buttons=y(180);place(a.combo,m,y(98),width-buttons-gap,y(240));place(a.browse,r.right-m-buttons,y(98),y(100),y(32));place(a.refresh,r.right-m-y(70),y(98),y(70),y(32));
 place(a.phase,m,y(144),width,y(32));place(a.metrics,m,y(181),width,y(51));
 place(a.warning,m,y(244),width,y(44));
 place(a.start,m,y(305),y(275),y(39));place(a.cancel,m+y(287),y(305),y(100),y(39));place(a.log,r.right-m-y(224),y(305),y(108),y(39));place(a.copy,r.right-m-y(108),y(305),y(108),y(39));
 place(a.detail,m,y(362),width,std::max(y(64),static_cast<int>(r.bottom)-y(362)-m));
}
void Buttons(App& a){const int i=static_cast<int>(SendMessageW(a.combo,CB_GETCURSEL,0,0));const bool valid=i>=0&&static_cast<size_t>(i)<a.installs.candidates.size()&&a.installs.candidates[static_cast<size_t>(i)].supported;
 EnableWindow(a.start,!a.busy&&!a.monitor&&!a.closing&&valid);EnableWindow(a.browse,!a.busy&&!a.monitor&&!a.closing);EnableWindow(a.refresh,!a.busy&&!a.monitor&&!a.closing);EnableWindow(a.combo,!a.busy&&!a.monitor&&!a.closing);EnableWindow(a.cancel,a.busy&&!a.closing);EnableWindow(a.log,!a.logpath.empty());}
std::wstring Stage(const SessionEvent& e){if(e.terminal)return L"游戏已退出，可再次启动";if(!e.has_status){if(e.message==L"waiting_process")return L"等待 Steam 启动 GMod…";return L"等待引擎模块就绪…";}const auto& s=e.status;
 if(s.state==2)return L"512 槽位已激活 · 原生加载，无需 Lua";
 if(s.state==4)return L"部分启用：需要退出并重新启动游戏";
 if(s.state>=3)return L"初始化被拒绝或失败，请查看诊断";
 switch(s.stage){case 1:return L"等待引擎…";case 2:return L"等待声音设备初始化…";case 3:return L"检查安装与同步条件…";case 4:return L"准备空声音表…";case 5:return L"初始化混音桥…";case 6:return L"初始化快照桥…";case 7:return L"迁移声音存储…";case 8:return L"启用 512 槽位…";default:return L"正在初始化…";}
}
void Select(App& a){const auto i=static_cast<int>(SendMessageW(a.combo,CB_GETCURSEL,0,0));if(i>=0&&static_cast<size_t>(i)<a.installs.candidates.size()){const auto& c=a.installs.candidates[static_cast<size_t>(i)];Text(a.phase,c.supported?L"引擎版本兼容，可启动":L"发现游戏，但当前引擎不受支持");a.diagnostics=L"游戏目录："+c.root+L"\r\n来源："+c.source+L"\r\n检查："+c.reason+L"\r\n模块："+a.config.module;Text(a.detail,a.diagnostics);}Buttons(a);}
void Consume(App& a){std::deque<Event> events;{std::lock_guard<std::mutex> lock(a.mutex);events.swap(a.events);}for(auto& e:events){if(e.kind==Event::Found){a.installs=std::move(e.discovery);a.config=std::move(e.config);SendMessageW(a.combo,CB_RESETCONTENT,0,0);int selected=-1;for(size_t i=0;i<a.installs.candidates.size();++i){const auto& c=a.installs.candidates[i];const auto label=(c.supported?L"✓ ":L"不兼容 · ")+c.root;SendMessageW(a.combo,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(label.c_str()));if(!a.config.game.empty()&&SamePath(c.game,a.config.game))selected=static_cast<int>(i);}if(selected<0&&a.installs.candidates.size()==1)selected=0;SendMessageW(a.combo,CB_SETCURSEL,selected,0);Select(a);if(a.installs.candidates.empty()){Text(a.phase,L"未找到 GMod，请选择游戏文件夹");a.diagnostics=L"未发现有效安装。可选择 GarrysMod 根目录。";for(const auto& d:a.installs.diagnostics)a.diagnostics+=L"\r\n"+d;Text(a.detail,a.diagnostics);}else if(selected<0)Text(a.phase,L"发现多个安装，请选择路径");}
 else if(e.kind==Event::Status){a.logpath=e.session.log_path;Text(a.phase,Stage(e.session));a.diagnostics=e.session.has_status?FormatStatus(e.session.status):e.session.message;a.diagnostics+=L"\r\nPID："+std::to_wstring(e.session.pid)+L"\r\n日志："+a.logpath;Text(a.detail,a.diagnostics);
  if(e.session.has_status){a.sampled=GetTickCount64();a.monitor=e.session.status.state==2;const auto& s=e.session.status;std::wostringstream m;m<<L"容量 "<<s.capacity<<L"  |  ";if(s.diagnostic_flags&kDiagCountsValid)m<<L"活跃 "<<s.active<<L"（动态 "<<s.dynamic<<L" / 静态 "<<s.statics<<L"）  |  扫描范围 "<<s.total;else m<<L"声音计数暂不可用";m<<L"\r\n混音帧 "<<s.frames<<L"  |  mixed "<<s.mixed<<L"  |  错误 "<<s.errors<<L" / 回退 "<<s.fallback<<L"  |  刚刚查询";Text(a.metrics,m.str());}
  if(e.session.terminal){a.monitor=false;a.sampled=0;Text(a.metrics,L"游戏已退出，上一会话数据已清除");}}
 else if(e.kind==Event::Error){a.monitor=false;a.sampled=0;Text(a.phase,L"操作未完成：请查看诊断");Text(a.metrics,L"当前状态未确认；旧计数不作为健康状态");a.diagnostics=e.message+L"\r\n"+a.diagnostics;Text(a.detail,a.diagnostics);}
 else a.busy=false;
 }Buttons(a);}
std::wstring BrowseRoot(HWND owner){IFileOpenDialog* dialog=nullptr;if(FAILED(CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog))))throw std::runtime_error("folder dialog unavailable");struct Release{IFileOpenDialog* d;~Release(){d->Release();}}release{dialog};DWORD options{};dialog->GetOptions(&options);dialog->SetOptions(options|FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM);dialog->SetTitle(L"选择 GarrysMod 根目录");if(FAILED(dialog->Show(owner)))return {};IShellItem* item=nullptr;if(FAILED(dialog->GetResult(&item)))return {};PWSTR path=nullptr;std::wstring out;if(SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH,&path))){out=path;CoTaskMemFree(path);}item->Release();return out;}
void Clipboard(HWND owner,const std::wstring& text){if(!OpenClipboard(owner))throw std::runtime_error("clipboard unavailable");struct Close{~Close(){CloseClipboard();}}close;const size_t bytes=(text.size()+1)*sizeof(wchar_t);HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,bytes);if(!memory)throw std::runtime_error("clipboard allocation failed");void* data=GlobalLock(memory);if(!data){GlobalFree(memory);throw std::runtime_error("clipboard lock failed");}memcpy(data,text.c_str(),bytes);GlobalUnlock(memory);if(!EmptyClipboard()||!SetClipboardData(CF_UNICODETEXT,memory)){GlobalFree(memory);throw std::runtime_error("clipboard write failed");}}
void BeginLaunch(App& a){const auto i=static_cast<int>(SendMessageW(a.combo,CB_GETCURSEL,0,0));if(i<0||static_cast<size_t>(i)>=a.installs.candidates.size()||!a.installs.candidates[static_cast<size_t>(i)].supported)return;
 auto c=a.config;const auto& candidate=a.installs.candidates[static_cast<size_t>(i)];c.game=candidate.game;c.engine=candidate.engine;c.acknowledged=true;c.clear_once=true;
 try{SaveConfig(Home().wstring(),c);}catch(const std::exception&){if(MessageBoxW(a.window,L"无法保存配置。是否仅本次使用？下次需要重新确认。",L"配置目录不可写",MB_YESNO|MB_ICONWARNING)!=IDYES)return;}
 a.cancel_requested.store(false);a.busy=true;a.sampled=0;Text(a.phase,L"正在启动…");Text(a.metrics,L"等待首次有效查询");Buttons(a);a.Queue({Command::Launch,{},c});
}
LRESULT CALLBACK WindowProc(HWND window,UINT message,WPARAM w,LPARAM l){App* a=reinterpret_cast<App*>(GetWindowLongPtrW(window,GWLP_USERDATA));if(message==WM_NCCREATE){a=static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(l)->lpCreateParams);a->window=window;SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(a));}
 if(!a)return DefWindowProcW(window,message,w,l);
 try{switch(message){case WM_CREATE:
 a->title=Control(*a,L"STATIC",L"Channel Expand",SS_LEFT);a->version=Control(*a,L"STATIC",L"图形 RC3 · 核心 0.11.0 RC1 · 64 动态 + 448 静态",SS_LEFT);
 a->combo=Control(*a,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP|WS_VSCROLL,Install);a->browse=Control(*a,L"BUTTON",L"选择文件夹",WS_TABSTOP,Browse);a->refresh=Control(*a,L"BUTTON",L"刷新",WS_TABSTOP,Refresh);
 a->phase=Control(*a,L"STATIC",L"正在寻找 Steam 游戏安装…",SS_LEFT);a->metrics=Control(*a,L"STATIC",L"未启用 · 等待启动",SS_LEFT);
 a->warning=Control(*a,L"STATIC",L"实验 RC：网络语音、音乐与长期稳定性仍待验证。\r\n关闭此窗口不会撤销扩容；游戏退出后恢复。",SS_LEFT);
 a->start=Control(*a,L"BUTTON",L"启动 GMod 并启用 512 槽位",BS_DEFPUSHBUTTON|WS_TABSTOP,Start);a->cancel=Control(*a,L"BUTTON",L"取消等待",WS_TABSTOP,Cancel);a->log=Control(*a,L"BUTTON",L"打开日志",WS_TABSTOP,Log);a->copy=Control(*a,L"BUTTON",L"复制诊断",WS_TABSTOP,Copy);a->detail=Control(*a,L"EDIT",L"",ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_TABSTOP);
 Fonts(*a);Layout(*a);Buttons(*a);SetTimer(window,1,1000,nullptr);return 0;
 case WM_SIZE:Layout(*a);return 0;
 case WM_DPICHANGED:{a->dpi=HIWORD(w);const auto r=reinterpret_cast<RECT*>(l);SetWindowPos(window,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE);Fonts(*a);Layout(*a);return 0;}
 case WM_GETMINMAXINFO:{auto info=reinterpret_cast<MINMAXINFO*>(l);info->ptMinTrackSize={Scale(*a,760),Scale(*a,580)};return 0;}
 case EventMessage:Consume(*a);if(a->closing&&a->done.load()){if(a->worker.joinable())a->worker.join();DestroyWindow(window);}return 0;
 case WM_TIMER:if(a->closing&&a->done.load()){if(a->worker.joinable())a->worker.join();DestroyWindow(window);}else if(a->sampled&&GetTickCount64()-a->sampled>6000)Text(a->metrics,L"查询尚未完成：显示状态已过期，等待当前请求结束");return 0;
 case WM_COMMAND:switch(LOWORD(w)){case Install:if(HIWORD(w)==CBN_SELCHANGE)Select(*a);break;case Refresh:a->busy=true;Buttons(*a);a->Queue({Command::Discover,{},{}});break;case Browse:{const auto root=BrowseRoot(window);if(!root.empty()){a->busy=true;Buttons(*a);a->Queue({Command::Manual,root,{}});}break;}case Start:BeginLaunch(*a);break;case Cancel:a->cancel_requested.store(true);a->session.Cancel();Text(a->phase,L"正在结束等待；已启用部分保持至游戏退出");break;case Log:if(!a->logpath.empty()){const auto result=reinterpret_cast<INT_PTR>(ShellExecuteW(window,L"open",a->logpath.c_str(),nullptr,nullptr,SW_SHOWNORMAL));if(result<=32)throw std::runtime_error("cannot open log");}break;case Copy:Clipboard(window,a->diagnostics);break;}return 0;
 case WM_CLOSE:if(a->smoke){DestroyWindow(window);return 0;}a->closing=true;a->stop.store(true);a->session.Cancel();a->wake.notify_all();Text(a->phase,L"正在结束监控，请等待当前请求完成…");Buttons(*a);if(a->done.load()){if(a->worker.joinable())a->worker.join();DestroyWindow(window);}return 0;
 case WM_DESTROY:KillTimer(window,1);PostQuitMessage(0);return 0;
 default:return DefWindowProcW(window,message,w,l);}
 }catch(const std::exception& ex){Text(a->phase,L"界面操作失败");Text(a->detail,Wide(ex.what()));return 0;}
}
bool Capture(App& a){RECT rect{};GetWindowRect(a.window,&rect);const int width=rect.right-rect.left,height=rect.bottom-rect.top;HDC screen=GetDC(nullptr),memory=CreateCompatibleDC(screen);HBITMAP bitmap=CreateCompatibleBitmap(screen,width,height);const auto old=SelectObject(memory,bitmap);RECT fill{0,0,width,height};FillRect(memory,&fill,reinterpret_cast<HBRUSH>(COLOR_WINDOW+1));SendMessageW(a.window,WM_PRINT,reinterpret_cast<WPARAM>(memory),PRF_CLIENT|PRF_ERASEBKGND|PRF_CHILDREN);const bool printed=true;BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=width;info.bmiHeader.biHeight=-height;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;std::vector<BYTE> pixels(static_cast<size_t>(width)*height*4);SelectObject(memory,old);const bool read=GetDIBits(memory,bitmap,0,static_cast<UINT>(height),pixels.data(),&info,DIB_RGB_COLORS)!=0;DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(nullptr,screen);if(!printed||!read)return false;
 BITMAPFILEHEADER file{};file.bfType=0x4d42;file.bfOffBits=sizeof(file)+sizeof(info.bmiHeader);file.bfSize=file.bfOffBits+static_cast<DWORD>(pixels.size());std::ofstream out(Home()/L"gui-self-check.bmp",std::ios::binary);out.write(reinterpret_cast<const char*>(&file),sizeof(file));out.write(reinterpret_cast<const char*>(&info.bmiHeader),sizeof(info.bmiHeader));out.write(reinterpret_cast<const char*>(pixels.data()),static_cast<std::streamsize>(pixels.size()));return static_cast<bool>(out);}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR command,int show){App a;try{
 a.smoke=std::wstring(command)==L"--ui-self-check";SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);const HRESULT co=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(co))throw std::runtime_error("COM initialization failed");struct Co{~Co(){CoUninitialize();}}cleanup;
 INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_STANDARD_CLASSES};InitCommonControlsEx(&controls);WNDCLASSEXW cls{};cls.cbSize=sizeof(cls);cls.hInstance=instance;cls.lpfnWndProc=WindowProc;cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);cls.hIcon=LoadIconW(nullptr,IDI_APPLICATION);cls.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);cls.lpszClassName=L"ChannelExpandLauncher";if(!RegisterClassExW(&cls))throw std::runtime_error("window registration failed");
 a.dpi=static_cast<int>(GetDpiForSystem());const auto window=CreateWindowExW(0,cls.lpszClassName,L"Channel Expand — GMod 声音槽位",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,Scale(a,880),Scale(a,650),nullptr,nullptr,instance,&a);if(!window)throw std::runtime_error("window creation failed");a.dpi=static_cast<int>(GetDpiForWindow(window));Fonts(a);Layout(a);
 if(a.smoke){a.installs.candidates.push_back({L"L:\\SteamLibrary\\steamapps\\common\\GarrysMod",L"",L"",L"",L"UI layout check only",L"No game process used",true});SendMessageW(a.combo,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(a.installs.candidates[0].root.c_str()));SendMessageW(a.combo,CB_SETCURSEL,0,0);Select(a);if(GetDlgItem(window,Ack)||GetDlgItem(window,Clear))throw std::runtime_error("confirmation controls must be absent");Buttons(a);if(!IsWindowEnabled(a.start)||IsWindowEnabled(a.cancel))throw std::runtime_error("direct launch button state failed");a.installs.candidates[0].supported=false;Buttons(a);if(IsWindowEnabled(a.start))throw std::runtime_error("unsupported launch enabled");a.installs.candidates[0].supported=true;Buttons(a);SetWindowPos(window,nullptr,0,0,Scale(a,880),Scale(a,650),SWP_NOZORDER|SWP_NOACTIVATE);if(!Capture(a))throw std::runtime_error("actual Win32 window capture failed");DestroyWindow(window);std::ofstream(Home()/L"gui-self-check.txt")<<"GUI_SELF_CHECK_PASS: actual hidden Win32 controls/layout/direct launch/unsupported gate/capture; no game launched\n";
 }else{ShowWindow(window,show);UpdateWindow(window);a.worker=std::thread([&a]{a.Run();});a.busy=true;Buttons(a);a.Queue({Command::Discover,{},{}});}
 MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
 if(a.worker.joinable()){a.stop.store(true);a.session.Cancel();a.wake.notify_all();a.worker.join();}if(a.font)DeleteObject(a.font);if(a.heading)DeleteObject(a.heading);return 0;
 }catch(const std::exception& ex){a.stop.store(true);a.session.Cancel();a.wake.notify_all();if(a.worker.joinable())a.worker.join();if(a.smoke){std::ofstream(Home()/L"gui-self-check.txt")<<"GUI_SELF_CHECK_FAIL: "<<ex.what();}else MessageBoxW(nullptr,Wide(ex.what()).c_str(),L"Channel Expand",MB_OK|MB_ICONERROR);return 1;}}
